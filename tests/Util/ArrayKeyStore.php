<?php

namespace Firebase\Auth\Token\Tests\Util;

use Firebase\Auth\Token\Domain\KeyStore;

class ArrayKeyStore implements KeyStore
{
    private $keys;

    public function __construct(array $keys)
    {
        $this->keys = $keys;
    }

    public function get($keyId, $type = null)
    {
        $keys = $type ? $this->keys[$type] ?? [] : $this->keys;

        if (!array_key_exists($keyId, $keys)) {
            throw new \OutOfBoundsException(sprintf('Key with ID "%s" not found.', $keyId));
        }

        return $keys[$keyId];
    }
}
