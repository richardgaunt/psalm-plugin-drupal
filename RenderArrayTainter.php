<?php

namespace mortenson\PsalmPluginDrupal;

use PhpParser\Node\ArrayItem;
use Psalm\Plugin\EventHandler\Event\AddRemoveTaintsEvent;
use Psalm\Plugin\EventHandler\RemoveTaintsInterface;
use Psalm\Type\TaintKind;

class RenderArrayTainter implements RemoveTaintsInterface
{
    public static function removeTaints(AddRemoveTaintsEvent $event): int
    {
        $item = $event->getExpr();
        if (!($item instanceof ArrayItem)) {
            return 0;
        }
        $item_key_value = '';
        if ($item->key) {
            $item_key_type = $event->getStatementsSource()->getNodeTypeProvider()->getType($item->key);
            if ($item_key_type && $item_key_type->isSingleStringLiteral()) {
                $item_key_value = $item_key_type->getSingleStringLiteral()->value;
            }
        }

        $dangerous_keys = [
            // Code execution.
            '#access_callback',
            '#ajax',
            '#after_build',
            '#element_validate',
            '#lazy_builder',
            '#post_render',
            '#pre_render',
            '#process',
            '#submit',
            '#validate',
            '#value_callback',
            '#file_value_callbacks',
            '#date_date_callbacks',
            '#date_time_callbacks',
            '#captcha_validate',
            // Cross site scripting.
            '#template',
            '#children',
        ];

        if (
            isset($item_key_value[0])
            && $item_key_value[0] === '#'
            && !in_array($item_key_value, $dangerous_keys, true)
        ) {
            // We could/should use a custom taint type here.
            return TaintKind::INPUT_HTML;
        }

        return 0;
    }
}
