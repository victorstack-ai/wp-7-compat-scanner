<?php
/**
 * Plugin Name: Sample Plugin
 */

add_filter('allowed_block_types', function ($allowed_blocks) {
    return $allowed_blocks;
});

add_filter('block_editor_settings', function ($settings) {
    return $settings;
});

$legacy_callback = create_function('$value', 'return $value;');
