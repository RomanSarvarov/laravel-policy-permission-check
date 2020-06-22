<?php

namespace Sarvarov\LaravelPolicyPermissionCheck;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Sarvarov\LaravelPolicyPermissionCheck\Helpers\PermissionCheckHelper;

/**
 * Class MagicPolicy
 *
 * Laravel abstract policy class with magic methods and helpers.
 *
 * @author Roman Sarvarov <roman@sarvarov.dev>
 * @url https://sarvarov.dev/laravel/policy-permission-check.html
 * @package Sarvarov\LaravelPolicyPermissionCheck
 */
abstract class MagicPolicy
{
    /**
     * Define it if your policy and model classes has different names.
     *
     * @var string Permission subject name.
     */
    protected $permissionSubject;

    /**
     * @var string Called policy method.
     */
    private $calledMethod;

    /**
     * @var string Called proxy method.
     */
    private $calledProxy;

    /**
     * Processes all called methods (if they do not exist).
     * Searches for a resolution based on the method being called.
     *
     * Example:
     * If call `viewAny` method (that does not exists) in the `PostPolicy` class,
     * it will automatically checks permission with `view any posts` key.
     *
     * If your app has different conventions for permissions, you can easy adapt it.
     *
     * @param  string  $method
     * @param  array  $arguments
     *
     * @return bool
     * @throws \Throwable
     */
    public function __call($method, $arguments)
    {
        /** @var User $user */
        $user = $arguments[0] ?? null;

        throw_unless(
            $user instanceof User,
            \InvalidArgumentException::class,
            'Bad user model.'
        );

        /** @var Model|null $model */
        $model = $arguments[1] ?? null;

        $this->calledMethod = $method;

        /*
         * Proxy methods check.
         */
        $proxies = $this->getProxies();

        if ($proxies) {
            foreach ($proxies as $to => $from) {
                if (in_array($method, Arr::wrap($from), true)) {
                    $toExploded = explode(':', $to);

                    [$to, $keepBaseMethodName] = [$toExploded[0], $toExploded[1] ?? true];

                    if (is_string($keepBaseMethodName) && $keepBaseMethodName === 'false') {
                        $this->calledMethod = $to;
                    }

                    $this->calledProxy = $method;

                    return $this->$to(...$arguments);
                }
            }
        }

        /*
         * Get action my method name.
         */
        $action = PermissionCheckHelper::getActionByMethodName($method);

        return $this->checkPermission($user, $action, $model);
    }

    /**
     * Checks the user's permission to the action.
     *
     * @param  User  $user
     * @param  string  $action
     * @param  Model|string|null  $subject
     * @return bool
     */
    protected function checkPermission(User $user, $action = null, $subject = null)
    {
        try {
            if (!$action) {
                return $this->checkPermissionByMethodName($user, $this->getCalledMethod(), $subject);
            }

            $can = $user->can(
                PermissionCheckHelper::key(
                    $this->getSubject($subject),
                    $action
                )
            );

            $this->calledMethod = null;

            return $can;
        } catch (\Throwable $e) {
            return false;
        }
    }

	/**
	 * Checks the user's permission by method name.
	 *
	 * @param User $user
	 * @param $method
	 * @param null $subject
	 *
	 * @return bool
	 */
    protected function checkPermissionByMethodName(User $user, $method, $subject = null)
    {
        $action = PermissionCheckHelper::getActionByMethodName(
            $this->getCalledMethod()
        );

        return $this->checkPermission($user, $method, $subject);
    }

    /**
     * Checks the user's permission with addition proxy method permission to action.
     *
     * @param  User  $user
     * @param  string  $action
     * @param  null  $subject
     * @return bool
     */
    protected function checkProxiedPermission(User $user, $action, $subject = null)
    {
        try {
            $calledProxy = $this->calledProxy();

            throw_if(
                is_null($calledProxy),
                \InvalidArgumentException::class,
                'Cannot get called proxy method.'
            );

            return $this->checkPermission(
                $user,
                PermissionCheckHelper::getProxiedAction($calledProxy, $action),
                $subject
            );
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Returns subject name.
     *
     * If subject is string, it will return exact same.
     * If subject is model or NULL, it will return plural lower cased model name.
     *
     * @param  null  $subject
     * @return string|null
     * @throws \Throwable
     */
    private function getSubject($subject = null)
    {
        if (is_string($subject)) {
            return $subject;
        }

        /*
         * Define protected $permissionSubject if your policy
         * and model have different names.
         */
        if ($this->permissionSubject) {
            return $this->permissionSubject;
        }

        /*
         * Magic begins here...
         */
        if (is_null($subject)) {
            /*
             * Takes the name of the current policy class and removes `Policy` of the end.
             *
             * SuperUserPolicy -> SuperUser
             */
            $subject = Str::replaceLast(
                'Policy',
                '',
                static::class
            );
        }

        $this->permissionSubject = PermissionCheckHelper::subject($subject);

        return $this->permissionSubject;
    }

    /**
     * Returns called proxy method.
     *
     * @return string|null
     */
    protected function calledProxy()
    {
        if (!$this->calledProxy) {
            return $this->calledProxy;
        }

        $calledMethod = $this->getCalledMethod();

        if (array_key_exists($calledMethod.':false', $this->getProxies())) {
            return $calledMethod;
        }

        return $this->calledProxy;
    }

    /**
     * Returns called policy method.
     *
     * @return bool|string
     * @throws \RuntimeException
     */
    private function getCalledMethod()
    {
        if ($this->calledMethod) {
            return $this->calledMethod;
        }

        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5) as $trace) {
            if (basename($trace['file'] ?? '') === 'Gate.php') {
                return $trace['function'] ?? false;
            }
        }

        throw new \RuntimeException('Cannot get called method.');
    }

    /**
     * Returns proxy methods.
     *
     * @return array
     */
    private function getProxies()
    {
        /*
         * Example of defining proxy methods in policy class:
         *
         * protected $proxies = [
         *     'manage' => ['update', 'delete'],
         * ];
        */

        return $this->proxies ?? [];
    }
}
