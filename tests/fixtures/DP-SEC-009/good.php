<?php
/**
 * DP-SEC-009 good: prepare() with %s and %i.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Visits by referrer.
 *
 * @param string $referrer Referrer.
 * @return array
 */
function dp_get_visits( $referrer ) {
	global $wpdb;
	return $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE referrer = %s', $wpdb->prefix . 'dp_referrers', $referrer ) );
}

/**
 * Visits sorted by an allowlisted column.
 *
 * @param string $orderby Column.
 * @return array
 */
function dp_get_sorted( $orderby ) {
	global $wpdb;
	$allowed = array( 'created_at', 'hits' );
	$column  = in_array( $orderby, $allowed, true ) ? $orderby : 'created_at';
	return $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i ORDER BY %i DESC', $wpdb->prefix . 'dp_referrers', $column ) );
}
