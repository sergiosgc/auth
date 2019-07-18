<?php

namespace sergiosgc\auth;


class AuthSingleton {
    public static function getAuth() {
        static $singleton = null;
        if (is_null($singleton)) {
            $reflect  = new \ReflectionClass('\sergiosgc\auth\Auth');
            $singleton = $reflect->newInstanceArgs(func_get_args());
        }
        return $singleton;
    }
}