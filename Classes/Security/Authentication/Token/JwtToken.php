<?php
namespace JohannesSteu\JwtAuth\Security\Authentication\Token;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;

/**
 * The flow authentication token representation for a JWT token
 *
 * An authentication token used for JWT authentication. Will accept the JWT encoded string
 * from HTTP headers (with <code>X-JWT</code>)
 */
class JwtToken extends AbstractToken implements SessionlessTokenInterface
{
    /**
     * The jwt credentials
     *
     * @var array
     * @Flow\Transient
     */
    protected $credentials = ['jwt' => ''];

    /**
     * @var array
     */
    protected $payload;

    /**
     * @return array
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param array $payload
     */
    public function setPayload(array $payload)
    {
        $this->payload = $payload;
    }

    /**
     * @param ActionRequest $actionRequest
     * @return void
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        // This token requires a jwt encoded string in a 'X-JWT' Header
        if ($actionRequest->getHttpRequest()->hasHeader('X-Jwt')) {
            // set the jwt encoded string
            $this->credentials['jwt'] = $actionRequest->getHttpRequest()->getHeader('X-Jwt');
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }
    }
}
