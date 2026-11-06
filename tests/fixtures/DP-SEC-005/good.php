<?php
/**
 * DP-SEC-005 good: callables from a server-side map.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Formats a value with a callable picked from an allowlist map.
 */
function dp_ajax_format() {
	check_ajax_referer( 'dp_format' );
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_die();
	}
	$formatters = array(
		'upper' => 'strtoupper',
		'lower' => 'strtolower',
	);
	$key        = isset( $_POST['formatter'] ) ? sanitize_key( wp_unslash( $_POST['formatter'] ) ) : '';
	$value      = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';
	$formatter  = isset( $formatters[ $key ] ) ? $formatters[ $key ] : 'strtolower';
	wp_send_json_success( call_user_func( $formatter, $value ) );
}
