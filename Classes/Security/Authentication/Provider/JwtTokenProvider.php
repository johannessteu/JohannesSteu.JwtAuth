<?php
namespace Yeebase\t3n\Common\Security\Authentication\Provider;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use JohannesSteu\JwtAuth\Security\Authentication\Token\JwtToken;
use Firebase\JWT\JWT;

class JwtTokenProvider extends AbstractProvider
{

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\InjectConfiguration(package="JohannesSteu.JwtAuth", path="sharedSecret")
     */
    protected $secret;

    /**
     * Returns the class names of the tokens this provider is responsible for.
     */
    public function getTokenClassNames()
    {
        return [JwtToken::class];
    }

    /**
     * Authenticate a JwtToken
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @return void
     * @throws UnsupportedAuthenticationTokenException
     * @throws AccessDeniedException
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        // get the encoded string from the token
        $credentials = $authenticationToken->getCredentials();

        if (!is_array($credentials) || !isset($credentials['jwt'])) {
            // Mark this token as no credentials given as we expect a jwt token here
            $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            return;
        }

        $jwtPayload = null;
        try {
            // Decode the jwt payload with the configured secret
            $jwtPayload = (array)JWT::decode($credentials['jwt'], $this->secret, ['HS256']);
        } catch (\Exception $e) {
            // if the string can not be decoded it is not encoded with the correct secret
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
        }

        // we expect in the payload a key 'accountIdentifier' wich can contain any string
        if ($jwtPayload === null || !isset($jwtPayload['accountIdentifier'])) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        // Create a transient account with the provided account identifier. this
        // account is never persisted and will be created for each request
        // The decoded payload will be set inside the token
        $account = $this->createTransientAccount($jwtPayload['accountIdentifier']);
        $authenticationToken->setAccount($account);
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        $authenticationToken->setPayload($jwtPayload);
    }

    /**
     * Create a transient account
     *
     * @param $accountIdentifier
     * @param array $roleIdentifiers
     * @return Account
     */
    protected function createTransientAccount($accountIdentifier)
    {
        $account = new Account();
        $account->setAccountIdentifier($accountIdentifier);

        // This role can be used for your Policy.yaml configuration
        $account->addRole($this->policyService->getRole('JohannesSteu.JwtAuth:User'));
        $account->setAuthenticationProviderName($this->name);
        return $account;
    }
}
