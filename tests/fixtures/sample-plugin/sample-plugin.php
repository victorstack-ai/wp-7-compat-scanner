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

$maybe_page = get_page_by_title('About Us');
$content = wp_make_content_images_responsive('<p><img src="example.jpg" /></p>');

$legacy_callback = create_function('$value', 'return $value;');
