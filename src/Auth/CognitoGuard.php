<?php

namespace BlackBits\LaravelCognitoAuth\Auth;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Result;
use Carbon\Carbon;
use Illuminate\Auth\SessionGuard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Session\Session;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Support\Arr;
use Symfony\Component\HttpFoundation\Request;
use Illuminate\Contracts\Auth\Authenticatable;
use BlackBits\LaravelCognitoAuth\CognitoClient;
use BlackBits\LaravelCognitoAuth\Exceptions\InvalidUserModelException;

class CognitoGuard extends SessionGuard implements StatefulGuard
{
    /**
     * @var CognitoClient
     */
    protected $client;

    /**
     * @var array
     */
    protected $cognitoTokens = null;

    /**
     * CognitoGuard constructor.
     * @param string $name
     * @param CognitoClient $client
     * @param UserProvider $provider
     * @param Session $session
     * @param null|Request $request
     */
    public function __construct(
        string $name,
        CognitoClient $client,
        UserProvider $provider,
        Session $session,
        ?Request $request = null
    ) {
        $this->client = $client;
        parent::__construct($name, $provider, $session, $request);
    }

    /**
     * @param mixed $user
     * @param array $credentials
     * @return bool|Result
     * @throws InvalidUserModelException
     */
    protected function hasValidCredentials($user, $credentials)
    {
        /** @var Result $response */
        $result = $this->client->authenticate($credentials['email'], $credentials['password']);
        // Only create the user if single sign on is activated in the project
        if (config('cognito.use_sso') && $result !== false && $user === null) {
            $user = $this->createUser($credentials['email']);
        }

        if ($result && $user instanceof Authenticatable) {
            return $result;
        }

        return false;
    }

    /**
     * @param $email
     * @return Model
     * @throws InvalidUserModelException
     */
    private function createUser($email)
    {
        /** @var Result $userResult */
        $userResult = $this->client->getUser($email);
        $userAttributes = count($userResult->get('UserAttributes')) > 0 ? $userResult->get('UserAttributes') : [];
        $userFields = config('cognito.sso_user_fields');
        $userModel = config('cognito.sso_user_model');
        /** @var Model $user */
        $user = new $userModel;

        if (! $user instanceof Model) {
            throw new InvalidUserModelException('User model does not extend Eloquent Model class.');
        }

        foreach ($userAttributes as $userAttribute) {
            $name = $userAttribute['Name'];
            $value = $userAttribute['Value'];

            if (in_array($name, $userFields)) {
                $user->$name = $value;
            }
        }

        $user->save();

        return $user;
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @param  bool   $remember
     * @throws
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        $this->fireAttemptEvent($credentials, $remember);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        try{

            if ($result = $this->hasValidCredentials($user, $credentials)) {
                // Hook up for Single Sign On
                // If user is not registered yet the user above will be null but hasValidCredentials
                // will be true. After creating the user we need to retrieve it again from the database.
                if ($user === null) {
                    $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
                }

                $this->cognitoTokens = $this->addTokenExpiryTimes($result['AuthenticationResult']);

                $this->storeCognitoTokensInSession($this->cognitoTokens);

                $this->login($user, $remember);

                return $result;
            }
        }
        catch (CognitoIdentityProviderException $e){
            if($e->getAwsErrorCode() === $this->client::RESET_REQUIRED)
                throw $e;
            $this->fireFailedEvent($user, $credentials);

            return false;
        }

        // If the authentication attempt fails we will fire an event so that the user
        // may be notified of any suspicious attempts to access their account from
        // an unrecognized user. A developer may listen to this event as needed.

    }

    /**
     * Get the user's AWS Cognito access, id and refresh tokens.
     *
     * @return null|array
     */
    protected function getCognitoTokensFromSession()
    {
        if ($this->cognitoTokens) {
            return $this->cognitoTokens;
        }

        $tokens = $this->session->get($this->getCognitoTokensName());

        if (!$tokens) {
            return null;
        }

        $now = time();

        // If the access and/or id tokens have expired then we'll want to request new
        // ones using the refresh token.
        if ($tokens['ExpiresIn'] < $now) {

            // If the refresh token has also expired then we're unable to request new
            // tokens.
            if ($tokens['RefreshTokenExpires'] < $now) {
                $this->clearUserDataFromSession();
                return null;
            }

            $refreshToken = $tokens['RefreshToken'];
            $refreshTokenExp = $tokens['RefreshTokenExpires'];

            if (!$tokens = $this->client->refreshCognitoTokens($refreshToken)) {
                $this->clearUserDataFromSession();
                return null;
            }

            $tokens = $this->addTokenExpiryTimes($tokens, false);
            $tokens['RefreshToken'] = $refreshToken;
            $tokens['RefreshTokenExpires'] = $refreshTokenExp;

            $this->storeCognitoTokensInSession($tokens);
        }

        $this->cognitoTokens = $tokens;

        return $this->cognitoTokens;
    }


    /**
     * Add expiry date/times to a user's AWS Congnito tokens.
     *
     * @param array $tokens
     * @param bool $updateRefreshTokenExp
     * @return array
     */
    protected function addTokenExpiryTimes(array $tokens, $updateRefreshTokenExp = true)
    {
        $tokens['ExpiresIn'] = Carbon::now()->addSeconds($tokens['ExpiresIn'] - 10)->timestamp;

        if ($updateRefreshTokenExp) {

            $days = 30;

            $tokens['RefreshTokenExpires'] = Carbon::now()->addDays($days)->timestamp;
        }

        return $tokens;
    }

    /**
     * Store the tokens returned from a successful auth attempt in the session.
     *
     * @param array $tokens
     */
    protected function storeCognitoTokensInSession(array $tokens)
    {
        $this->session->put($this->getCognitoTokensName(), $tokens);
    }

    /**
     * Get a unique identifier for the auth tokens session value.
     *
     * @return string
     */
    public function getCognitoTokensName()
    {
        return 'login_' . $this->name . '_aws_tokens_' . sha1(static::class);
    }

    /**
     * Remove the user data from the session.
     */
    protected function clearUserDataFromSession()
    {
        $this->session->remove($this->getName());
        $this->session->remove($this->getCognitoTokensName());
    }

}
