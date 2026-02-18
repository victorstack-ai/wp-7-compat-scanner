<?php
/**
 * Plugin Name: Sample Plugin
 */

add_filter('allowed_block_types', function ($allowed_blocks) {
    return $allowed_blocks;
});

add_action('admin_head-post.php', function () {
    echo "<script>console.log('legacy')</script>";
});
