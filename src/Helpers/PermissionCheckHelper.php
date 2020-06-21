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
            'permission.key_pattern',
            '{action}{delimiter}{subject}'
        );
    }

    /**
     * Returns permission key.
     *
     * @param  string  $subject
     * @param  string  $action
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

        return config("permission.delimiters.between_{$needle}", ' ');
    }

    /**
     * Returns formatted subject name.
     *
     * @param  object|string  $subject
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

        /*
         * Converts from CamelCase to snake_case with a ' ' delimiter (instead of '_').
         *
         * SuperUser -> super user
         */
        $subject = Str::snake(
            class_basename($subject),
            self::getDelimiterFor('words')
        );

        /*
         * ... makes it plural.
         *
         * super user -> super users
         */
        $subject = Str::plural($subject);

        return $subject;
    }

    /**
     * Returns action name based on method name.
     *
     * @param  string  $method
     * @return string
     */
    public static function getActionByMethodName(string $method)
    {
        return Str::snake(
            $method,
            self::getDelimiterFor('words')
        );
    }
}
