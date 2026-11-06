<?php
/**
 * DP-SEC-010 bad: block attributes printed unescaped.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Renders a badge block.
 *
 * @param array $attributes Block attributes.
 */
function dp_render_badge( $attributes ) {
	$label = isset( $attributes['label'] ) ? $attributes['label'] : '';
	echo '<span class="dp-badge">' . $label . '</span>'; // expect: WordPress.Security.EscapeOutput.OutputNotEscaped
	printf( '<a href="%s">%s</a>', $attributes['url'], $label ); // expect: WordPress.Security.EscapeOutput.OutputNotEscaped
	_e( 'Read more', 'dp' ); // expect: WordPress.Security.EscapeOutput.UnsafePrintingFunction
}
