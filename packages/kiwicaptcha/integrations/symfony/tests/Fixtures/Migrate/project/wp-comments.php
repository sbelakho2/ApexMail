<?php
/**
 * Plugin Name: Acme Comment Guard
 * Description: Adds a reCAPTCHA check to the comment form and its
 * server-side submission path.
 */

const ACME_RECAPTCHA_SITEKEY = '6LfwKHQUAAAAAG_B4Lk8Ga8g2sS3HkdR2f7qO1Zx';
const ACME_RECAPTCHA_SECRET = '6LfwKHQUAAAAAK9secretvalue0000000000x';

function acme_comment_form_field() {
    echo '<div class="g-recaptcha" data-sitekey="' . esc_attr(ACME_RECAPTCHA_SITEKEY) . '"></div>';
    echo '<script src="https://www.google.com/recaptcha/api.js" async defer></script>';
}

function acme_verify_comment_token() {
    $token = isset($_POST['g-recaptcha-response']) ? sanitize_text_field(wp_unslash($_POST['g-recaptcha-response'])) : '';
    $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', [
        'body' => [
            'secret' => ACME_RECAPTCHA_SECRET,
            'response' => $token,
            'remoteip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
        ],
    ]);
    if (is_wp_error($response)) {
        return false;
    }
    $body = json_decode(wp_remote_retrieve_body($response), true);

    return is_array($body) && !empty($body['success']);
}
