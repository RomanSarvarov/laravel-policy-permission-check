<?php

namespace Sarvarov\LaravelPolicyPermissionCheck\Helpers;

use Illuminate\Support\Str;

/**
 * Class PermissionCheckHelper
 *
 * Custom helper for Laravel permissions.
 *
 * @author Roman Sarvarov <roman@sarvarov.dev>
 * @package Sarvarov\LaravelPolicyPermissionCheck\Helpers
 */
class PermissionCheckHelper
{
    /**
     * Returns permission key pattern.
     *
     * Example:
     * '{action}{delimiter}{subject}' -> view-any.articles
     * '{subject}{delimiter}{action}' -> articles.view-any
     *
     * @return string
     */
    private static function getPermissionKeyPattern()
    {
        return config(
            'permission.naming_rules.key_pattern',
            '{action}{delimiter}{subject}'
        );
    }

    /**
     * Returns permission key.
     *
     * @param  string  $subject
     * @param  string  $action
     *
     * @return string
     */
    public static function key($subject, $action)
    {
        $pattern = self::getPermissionKeyPattern();

        $replaceFrom = ['{action}', '{delimiter}', '{subject}'];

        $replaceTo = [
            $action,
            self::getDelimiterFor('subject_and_action'),
            $subject
        ];

        return str_replace($replaceFrom, $replaceTo, $pattern);
    }

    /**
     * Returns delimiter for permission name.
     *
     * @param  string  $needle
     *
     * @return \Illuminate\Config\Repository|mixed
     */
    public static function getDelimiterFor(string $needle)
    {
        /*
         * You can define delimiters in permission config:
         *
         * Examples:
         *
         * 1. For words in permission name:
         * ' ' -> view any blog articles
         * '-' -> view-any blog-articles
         *
         * 2. Between subject and action:
         * ' ' -> view-any blog-articles
         * '.' -> view-any.blog-articles
         *
         */

        return config("permission.naming_rules.delimiters.between_{$needle}", ' ');
    }

    /**
     * Returns formatted subject name.
     *
     * @param  object|string  $subject
     *
     * @return string
     * @throws \Throwable
     */
    public static function subject($subject)
    {
        throw_unless(
            is_object($subject) || is_string($subject),
            \InvalidArgumentException::class,
            'Bad permission subject.'
        );

        $subject = class_basename($subject);

        /*
         * Converts from CamelCase to snake_case with a ' ' delimiter (instead of '_').
         *
         * SuperUser -> super user
         */
        if (config('permission.naming_rules.subject_snake_case', true)) {
            $subject = Str::snake(
                $subject,
                self::getDelimiterFor('words')
            );
        } elseif (config('permission.naming_rules.subject_lower_case', true)) {
            $subject = Str::lower($subject);
        }

        /*
         * ... makes it plural.
         *
         * super user -> super users
         */
        if (config('permission.naming_rules.subject_plural', true)) {
            $subject = Str::plural($subject);
        }

        return $subject;
    }

    /**
     * Returns action name based on method name.
     *
     * @param  string  $method
     *
     * @return string
     */
    public static function getActionByMethodName(string $method)
    {
        if (config('permission.naming_rules.action_snake_case', true)) {
            return Str::snake(
                $method,
                self::getDelimiterFor('words')
            );
        }

        if (config('permission.naming_rules.action_lower_case', true)) {
            $method = Str::lower($method);
        }

        return $method;
    }

    /**
     * Get proxied action name.
     *
     * @param  string  $calledProxy
     * @param  string  $action
     *
     * @return string
     */
    public static function getProxiedAction(string $calledProxy, string $action)
    {
        $pasteAfter = config('permission.proxied_action_paste_after', true);

        return sprintf(
            $pasteAfter
                ? '%1$s%2$s%3$s'
                : '%3$s%2$s%1$s',
            self::getActionByMethodName($calledProxy),
            self::getDelimiterFor('words'),
            $action
        );
    }
}
