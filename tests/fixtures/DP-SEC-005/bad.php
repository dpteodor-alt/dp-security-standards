<?php
/**
 * DP-SEC-005 bad: code chosen or built at runtime.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Renders a stored template by evaluating it.
 *
 * @param string $template Template source.
 * @return mixed
 */
function dp_render_dynamic( $template ) {
	return eval( '?>' . $template ); // expect: dp-sec-005
}

$dp_sorter = create_function( '$a,$b', 'return $a <=> $b;' ); // expect: dp-sec-005

/**
 * Formats a value with a callable named by the client.
 */
function dp_ajax_format() {
	check_ajax_referer( 'dp_format' );
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_die();
	}
	$formatter = isset( $_POST['formatter'] ) ? sanitize_key( wp_unslash( $_POST['formatter'] ) ) : '';
	$value     = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';
	$content   = isset( $_POST['content'] ) ? wp_kses_post( wp_unslash( $_POST['content'] ) ) : '';
	echo esc_html( call_user_func( $formatter, $value ) ); // expect: dp-sec-005-taint
	echo wp_kses_post( do_shortcode( $content ) ); // expect: dp-sec-005-taint
	extract( $_POST ); // expect: dp-sec-005-taint
}
