<?php
namespace sergiosgc\auth;

class Exception extends \Exception { }
class AuthenticationException extends Exception { }
class NotLoggedInException extends Exception { }