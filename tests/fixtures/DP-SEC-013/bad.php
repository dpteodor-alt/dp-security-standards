<?php
/**
 * DP-SEC-013 bad: secrets and personal data made public.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

add_action(
	'init',
	function () {
		register_post_meta( 'dp_lead', 'dp_lead_email', array( 'type' => 'string', 'single' => true, 'show_in_rest' => true ) ); // expect: dp-sec-013
		register_meta( 'post', 'dp_youtube_api_key', array( 'single' => true, 'show_in_rest' => array( 'schema' => array( 'type' => 'string' ) ) ) ); // expect: dp-sec-013
		register_post_meta( 'dp_event', 'dp_event_venue', array( 'single' => true, 'show_in_rest' => true ) ); // expect: dp-sec-013-review
	}
);

add_action(
	'wp_enqueue_scripts',
	function () {
		wp_localize_script( 'dp-map', 'dpMap', array( 'apiKey' => get_option( 'dp_maps_key' ), 'restUrl' => esc_url_raw( rest_url( 'dp/v1/map' ) ) ) ); // expect: dp-sec-013-localize
	}
);
