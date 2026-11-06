<?php
/**
 * DP-SEC-010 good: escape late; exception messages are not output.
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
 * @throws InvalidArgumentException When the label is missing.
 */
function dp_render_badge( $attributes ) {
	if ( empty( $attributes['label'] ) ) {
		throw new InvalidArgumentException( 'Missing label for block ' . $attributes['id'] );
	}
	echo '<span ' . get_block_wrapper_attributes() . '>' . esc_html( $attributes['label'] ) . '</span>';
	printf( '<a href="%s">%s</a>', esc_url( $attributes['url'] ), esc_html( $attributes['label'] ) );
	esc_html_e( 'Read more', 'dp' );
}
