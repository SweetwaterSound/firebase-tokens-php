<?php

namespace Firebase\Auth\Token\Domain;

interface KeyStore
{
    /**
     * @param string $keyId
     * @param string $type
     *
     * @throws \OutOfBoundsException
     *
     * @return string
     */
    public function get($keyId, $type);
}
