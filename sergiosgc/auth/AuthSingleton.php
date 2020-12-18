<?php

namespace sergiosgc\auth;


class AuthSingleton {
    public static function getAuth() : \sergiosgc\auth\Auth {
        static $singleton = null;
        if (is_null($singleton)) {
            $reflect  = new \ReflectionClass('\sergiosgc\auth\Auth');
            $singleton = $reflect->newInstanceArgs(func_get_args());
        }
        return $singleton;
    }
    public static function __callStatic($name, $arguments) {
        if (!is_callable([static::getAuth(), $name])) throw new Exception(printf("Method \sergiosgc\auth\Auth::%s() does not exist", $name));
        return call_user_func_array([static::getAuth(), $name], $arguments);
    }
}