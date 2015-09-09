<?php
namespace Cargix1\OAuth2\Client\Provider;
use Cargix1\OAuth2\Client\Grant\RenewToken;
use Guzzle\Http\Exception\BadResponseException;
use League\OAuth2\Client\Exception\IDPException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Grant\RefreshToken;

class Shopify extends AbstractProvider
{

    public $api_key;

    public $scopes;

    public $redirectUri;

    public $state;

    public $shop;

    public $nonce;

    /**
     * Get a Square connect URL, depending on path.
     *
     * @param  string $store_url
     * @return string
     */
    protected function getConnectUrl()
    {
        return "https://".$this->shop.".myshopify.com/admin/oauth/authorize";
    }

    public function urlAuthorize()
    {
        return "https://".$this->shop.".myshopify.com/admin/oauth/authorize";
    }

    public function urlAccessToken()
    {
        return "https://".$this->shop.".myshopify.com/admin/oauth/access_token";
    }


    /**
     * Get the URL for rewnewing an access token.
     *
     * Square does not provide normal refresh tokens, and provides token
     * renewal instead.
     *
     * @return string
     */
    public function urlRenewToken()
    {
        return $this->getConnectUrl(sprintf(
            'oauth2/clients/%s/access-token/renew',
            $this->clientId
        ));
    }

    public function urlUserDetails(AccessToken $token)
    {
        // Todo
    }

    public function userDetails($response, AccessToken $token)
    {
        // Todo
    }

    /**
     * Provides support for token renewal instead of token refreshing.
     *
     * {@inheritdoc}
     *
     * @return AccessToken
     */
    public function getAccessToken($grant = 'authorization_code', $params = [])
    {
        if ($grant === 'refresh_token' || $grant instanceof RefreshToken) {
            throw new \InvalidArgumentException(
                'Square does not support refreshing tokens, please use renew_token instead'
            );
        }

        if (is_string($grant) && $grant === 'renew_token') {
            $grant = new RenewToken();
        }

        if (!($grant instanceof RenewToken)) {
            $token = parent::getAccessToken($grant, $params);
            dd($token);
            return $token;
        }

        $requestParams = $grant->prepRequestParams([], $params);

        $headers = [
            'Authorization' => 'Client ' . $this->clientSecret,
            'Accept'        => 'application/json',
        ];

        try {
            $request = $this->getHttpClient()
                ->post($this->urlRenewToken(), $headers)
                ->setBody(json_encode($requestParams), 'application/json')
                ->send();
            $response = $request->getBody();
        } catch (BadResponseException $e) {
            // @codeCoverageIgnoreStart
            $response = $e->getResponse()->getBody();
            // @codeCoverageIgnoreEnd
        }

        $result = json_decode($response, true);

        if (!empty($result['error']) || !empty($e)) {
            // @codeCoverageIgnoreStart
            throw new IDPException($result);
            // @codeCoverageIgnoreEnd
        }

        $result = $this->prepareAccessTokenResult($result);

        return $grant->handleResponse($result);
    }

    protected function fetchUserDetails(AccessToken $token)
    {
        $this->headers['Authorization'] = 'Bearer ' . $token->accessToken;
        $this->headers['Accept']        = 'application/json';

        return parent::fetchUserDetails($token);
    }

    protected function prepareAccessTokenResult(array $result)
    {
        $result['expires_in'] = strtotime($result['expires_at']) - time();

        return parent::prepareAccessTokenResult($result);
    }
}
