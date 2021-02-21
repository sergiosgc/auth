<?php
namespace sergiosgc\auth;

class Auth {
    protected $userId = null;
    protected $userObject = null;
    public $token = null;
    public function __construct($credentialCheckCallback, $userIdToObjectCallback, $secretKey, $validitySeconds = 500, $cookieName = 'sergiosgc_auth') {
        if (!is_callable($credentialCheckCallback)) throw new Exception('Credential check callback is not callable');
        if (!is_callable($userIdToObjectCallback)) throw new Exception('User ID to Object callback is not callable');
        $this->credentialCheckCallback = $credentialCheckCallback;
        $this->userIdToObjectCallback = $userIdToObjectCallback;
        $this->secretKey = $secretKey;
        $this->validitySeconds = $validitySeconds;
        $this->cookieName = $cookieName;
    }
    public function login() {
        $userId = call_user_func_array($this->credentialCheckCallback, func_get_args());
        if (is_null($userId) || $userId === false) throw new AuthenticationException('Authentication failure');
        $this->userId = $userId;
        $this->userObject = null;
        $this->token = $this->generateToken();
    }
    public function logout() {
        $this->userObject = $this->token = null;
        $this->userId = false;
    }
    public function resume() {
        if (!is_null($this->userId)) return;
        if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) $this->login(['username' => $_SERVER['PHP_AUTH_USER'], 'password' => $_SERVER['PHP_AUTH_PW']]);
        if (!$this->token && array_key_exists($this->cookieName, $_COOKIE)) $this->token = $_COOKIE[$this->cookieName];
        if (!$this->token && array_key_exists($this->cookieName, $_REQUEST)) $this->token = $_REQUEST[$this->cookieName];
        if (!$this->token) return $this->logout();
        $this->userId = $this->checkToken($this->token);
        if ($this->userId === false) return $this->logout();
        $this->token = $this->generateToken(); // Refresh token
    }
    public function isLoggedIn() {
        $this->resume();
        return $this->userId !== false;
    }
    public function assertLoggedIn($callbackOnFailure = null) {
        if ($this->isLoggedIn()) return;
        if (!is_null($callbackOnFailure)) call_user_func($callbackOnFailure);
        throw new NotLoggedInException();
    }
    public function sendCookie() {
        $cookie = [];
        $cookie[] = sprintf('%s=%s', $this->cookieName, $this->token ?: '--');
        if ($this->validitySeconds || is_null($this->token)) $cookie[] = sprintf('Max-Age=%s', is_null($this->token) ? -1 : $this->validitySeconds);
        if (array_key_exists('HTTPS', $_SERVER) && $_SERVER['HTTPS'] == 'on') $cookie[] = 'Secure';
        $cookie[] = 'Path=/';
        $cookie[] = 'Domain=' . $_SERVER['HTTP_HOST'];
        $cookie[] = 'SameSite=strict';
        header(sprintf('Set-Cookie: %s', implode('; ', $cookie)));
    }
    public function generateToken() {
        $payload = [ 'userid' => $this->userId, 'expires' => time() + $this->validitySeconds ];
        $payload = base64_encode(json_encode($payload, JSON_THROW_ON_ERROR));
        $signature = hash_hmac('sha256', $payload, $this->secretKey);
        return sprintf('%s:%s', $payload, $signature);
    }
    public function checkToken($token) {
        list($payload, $signature) = explode(':', $token, 2);
        if ($signature !== hash_hmac('sha256', $payload, $this->secretKey)) return false;
        $payload = base64_decode($payload);
        if (!$payload) return false;
        $payload = json_decode($payload, true);
        if (!$payload) return false;
        if (!array_key_exists('userid', $payload)) return false;
        return $payload['userid'];
    }
    public function getUser() {
        if (is_null($this->userId)) throw new NotLoggedInException('Not logged in. Cannot get user');
        if (!$this->userObject) {
            $this->userObject = call_user_func($this->userIdToObjectCallback, $this->userId);
            if (is_null($this->userObject) || $this->userObject === false) throw new Exception('Failure retrieving user object');
        }
        return $this->userObject;
    }
}
