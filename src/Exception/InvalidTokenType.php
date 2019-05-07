<?php

namespace Firebase\Auth\Token\Exception;

class InvalidTokenType extends \LogicException
{
    /**
     * @var string
     */
    private $type;

    public function __construct($type)
    {
        parent::__construct(sprintf('A token type of "%s" could not be found.', $type));

        $this->type = $type;
    }

    public function getType()
    {
        return $this->type;
    }
}
