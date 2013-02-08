<?php

class EncryptedPickle {

    protected static $DEFAULT_MAGIC = 'EP';

    protected static $VERSIONS = array(
        1 => array(
            'header_size' => 9,
            'header_format' => 'CCCCCCCCC',
            'header_format_unpack' => 'C9',
            'header' => array(
                'version',
                'signature_algorithm_id',
                'signature_passphrase_id',
                'encryption_algorithm_id',
                'encryption_passphrase_id',
                'serialization_algorithm_id',
                'compression_algorithm_id',
                'custom_id',
                'flags',
            ),
            'flags' => array(
                'timestamp',
                'unused_1',
                'unused_2',
                'unused_3',
                'unused_4',
                'unused_5',
                'unused_6',
                'unused_7',
            ),
            'timestamp_size' => 8,
        ),
    );

    protected static $DEFAULT_OPTIONS = array(
        'version' => 1,
        'signature_algorithm_id' => 0,
        'signature_passphrase_id' => 0,
        'encryption_algorithm_id' => 0,
        'encryption_passphrase_id' => 0,
        'serialization_algorithm_id' => 1,
        'compression_algorithm_id' => 0,
        'custom_id' => 0,
        'flags' => array(
            'timestamp' => False,
            'unused_1' => False,
            'unused_2' => False,
            'unused_3' => False,
            'unused_4' => False,
            'unused_5' => False,
            'unused_6' => False,
            'unused_7' => False,
        ),
    );

    protected static $DEFAULT_SIGNATURE = array(
        0 => array(
            'algorithm' => 'hmac-sha256',
            'salt_size' => 32,
            'pbkdf2_iterations' => 1,
            'pbkdf2_algorithm' => 'sha256',
        ),
    );

    protected static $DEFAULT_ENCRYPTION = array(
        0 => array(
            'algorithm' => 'aes-256-cbc',
            'salt_size' => 32,
            'pbkdf2_iterations' => 1,
            'pbkdf2_algorithm' => 'sha256',
        ),
    );

    protected static $DEFAULT_SERIALIZATION = array(
        0 => array(
            'algorithm' => 'no-serialization',
        ),
        1 => array(
            'algorithm' => 'json',
        ),
    );

    protected static $DEFAULT_COMPRESSION = array(
        0 => array(
            'algorithm' => 'no-compression',
        ),
        1 => array(
            'algorithm' => 'gzip-deflate',
            'level' => 9,
        ),
    );

    protected static $ALGORITHMS = array(
        'hmac-sha256' => array(
            'type' => 'hmac',
            'subtype' => 'sha256',
            'key_size' => 32,
            'hash_size' => 32,
        ),
        'hmac-sha384' => array(
            'type' => 'hmac',
            'subtype' => 'sha384',
            'key_size' => 32,
            'hash_size' => 48,
        ),
        'hmac-sha512' => array(
            'type' => 'hmac',
            'subtype' => 'sha512',
            'key_size' => 32,
            'hash_size' => 64,
        ),

        'aes-256-cbc' => array(
            'type' => 'aes',
            'subtype' => 'cbc',
            'key_size' => 32,
            'iv_size' => 16,
        ),

        'no-serialization' => array(
            'type' => 'no-serialization',
        ),
        'json' => array(
            'type' => 'json',
        ),

        'no-compression' => array(
            'type' => 'no-compression',
        ),
        'gzip-deflate' => array(
            'type' => 'gzip',
            'subtype' => 'deflate',
        ),
    );

    protected $signature_algorithms;
    protected $encryption_algorithms;
    protected $serialization_algorithms;
    protected $compression_algorithms;

    protected $signature_passphrases;
    protected $encryption_passphrases;

    protected $options;

    protected $magic;


    public function __construct(array $signature_passphrases = NULL, array $encryption_passphrases = NULL, array $options = NULL) {
        $this->signature_algorithms = self::$DEFAULT_SIGNATURE;
        $this->encryption_algorithms = self::$DEFAULT_ENCRYPTION;
        $this->serialization_algorithms = self::$DEFAULT_SERIALIZATION;
        $this->compression_algorithms = self::$DEFAULT_COMPRESSION;

        $this->signature_passphrases = self::update_array($signature_passphrases, array(), TRUE);
        $this->encryption_passphrases = self::update_array($encryption_passphrases, array(), TRUE);

        $this->magic = self::$DEFAULT_MAGIC;

        $this->options = self::$DEFAULT_OPTIONS;

        if ($options !== NULL) {
            $this->set_options($options);
        }
    }


    public function set_signature_passphrases(array $signature_passphrases = NULL) {
        $this->signature_passphrases = self::update_array($signature_passphrases, array(), TRUE);
    }


    public function get_signature_passphrases() {
        return $this->signature_passphrases;
    }


    public function set_encryption_passphrases(array $encryption_passphrases = NULL) {
        $this->encryption_passphrases = self::update_array($encryption_passphrases, array(), TRUE);
    }


    public function get_encryption_passphrases() {
        return $this->encryption_passphrases;
    }


    public function set_algorithms(array $signature = NULL, array $encryption = NULL, array $serialization = NULL, array $compression = NULL) {
        $this->signature_algorithms = self::update_array($signature, self::$DEFAULT_SIGNATURE);
        $this->encryption_algorithms = self::update_array($encryption, self::$DEFAULT_ENCRYPTION);
        $this->serialization_algorithms = self::update_array($serialization, self::$DEFAULT_SERIALIZATION);
        $this->compression_algorithms = self::update_array($compression, self::$DEFAULT_COMPRESSION);
    }


    public function get_algorithms() {
        return array(
            'signature' => $this->signature_algorithms,
            'encryption' => $this->encryption_algorithms,
            'serialization' => $this->serialization_algorithms,
            'compression' => $this->compression_algorithms,
        );
    }


    public function set_options(array $options = NULL) {
        $this->options = $this->_set_options($options);
    }


    private function _set_options(array $options = NULL) {
        if (empty($options)) {
            return $this->options;
        }

        if (array_key_exists('magic', $options)) {
            $this->set_magic($options['magic']);
            unset($options['magic']);
        }

        if (array_key_exists('flags', $options)) {
            $flags = $options['flags'];
            unset($options['flags']);
            foreach($flags as $k => $v) {
                if (!is_bool($v)) {
                    throw new Exception('Invalid flag type for: ' . var_export($k, TRUE));
                }
            }
        } else {
            $flags = $this->options['flags'];
        }

        if (array_key_exists('info', $options)) {
            unset($options['info']);
        }

        foreach ($options as $k => $v) {
            if (!is_integer($v)) {
                throw new Exception('Invalid option type for: ' . var_export($k, TRUE));
            }
            if ($v < 0 || $v > 255) {
                throw new Exception('Option value out of range for: ' . var_export($k, TRUE));
            }
        }

        $new_options = $this->options;
        $new_options = array_merge($this->options, $options);
        $new_options['flags'] = array_merge($new_options['flags'], $flags);

        return $new_options;
    }


    public function get_options() {
        return $this->options;
    }


    public function set_magic($magic) {
        if (is_string($magic) || $magic === NULL) {
            $this->magic = $magic;
        } else {
            throw new Exception('Invalid value for magic');
        }
    }


    public function get_magic() {
        return $this->magic;
    }


    public function seal($data, array $options = NULL) {
        $options = $this->_set_options($options);

        $data = $this->serialize_data($data, $options);
        $data = $this->compress_data($data, $options);
        $data = $this->encrypt_data($data, $options);
        $data = $this->add_header($data, $options);
        $data = $this->add_magic($data);
        $data = $this->sign_data($data, $options);
        $data = $this->remove_magic($data);
        $data = self::urlsafe_b64_encode($data);
        $data = $this->add_magic($data);

        return $data;
    }


    public function unseal($data, $return_options = FALSE) {
        $data = $this->remove_magic($data);
        $data = $this->urlsafe_b64_decode($data);
        $options = $this->read_header($data);
        $data = $this->add_magic($data);
        $data = $this->unsign_data($data, $options);
        $data = $this->remove_magic($data);
        $data = $this->remove_header($data, $options);
        $data = $this->decrypt_data($data, $options);
        $data = $this->decompress_data($data, $options);
        $data = $this->unserialize_data($data, $options);

        if ($return_options == TRUE) {
            return array($data, $options);
        } else {
            return $data;
        }
    }


    public function verify_signature($data) {
        $data = $this->read_magic($data);
        $data = self::urlsafe_b64_decode($data);
        $options = $this->read_header($data);
        $this->unsign_data($data, $options);
    }


    public function get_data_options($data, $verify_signature = TRUE) {
        $data = $this->read_magic($data);
        $data = self::urlsafe_b64_decode($data);
        $options = $this->read_header($data);

        if ($verify_signature) {
            $data = $this->unsign_data($data, $options);
        }

        return $options;
    }


    private function encode($data, $algorithm, $key = NULL) {
        if ($algorithm['type'] === 'hmac') {
            return $data . self::hmac_generate($data, $algorithm, $key);
        } elseif ($algorithm['type'] === 'aes') {
            return self::aes_encrypt($data, $algorithm, $key);
        } elseif ($algorithm['type'] === 'no-serialization') {
            return $data;
        } elseif ($algorithm['type'] === 'json') {
            return json_encode($data);
        } elseif ($algorithm['type'] === 'no-compression') {
            return $data;
        } elseif ($algorithm['type'] === 'gzip') {
            return self::zlib_compress($data, $algorithm);
        } else {
            throw new Exception('Algorithm not supported: ' . var_export($algorithm['type'], TRUE));
        }
    }


    private function decode($data, $algorithm, $key = NULL) {
        if ($algorithm['type'] === 'hmac') {
            $verify_signature = substr($data, -$algorithm['hash_size']);
            $data = substr($data, 0, -$algorithm['hash_size']);
            $signature = self::hmac_generate($data, $algorithm, $key);
            if (!self::is_equal($verify_signature, $signature)) {
                throw new Exception('Invalid signature');
            }
            return $data;
        } elseif ($algorithm['type'] === 'aes') {
            return self::aes_decrypt($data, $algorithm, $key);
        } elseif ($algorithm['type'] === 'no-serialization') {
            return $data;
        } elseif ($algorithm['type'] === 'json') {
            $data = json_decode($data, TRUE);
            if ($data === NULL) {
                throw new Exception('Error decoding JSON encoded data');
            }
            return $data;
        } elseif ($algorithm['type'] === 'no-compression') {
            return $data;
        } elseif ($algorithm['type'] === 'gzip') {
            return self::zlib_decompress($data, $algorithm);
        } else {
            throw new Exception('Algorithm not supported: ' . var_export($algorithm['type'], TRUE));
        }
    }


    private function sign_data($data, $options) {
        if (!array_key_exists($options['signature_algorithm_id'], $this->signature_algorithms)) {
            throw new Exception('Unknown signature algorithm id: ' . var_export($options['signature_algorithm_id'], TRUE));
        }

        $signature_algorithm = $this->signature_algorithms[$options['signature_algorithm_id']];

        $algorithm = self::get_algorithm_info($signature_algorithm);

        $key_salt = self::get_random_bytes($algorithm['salt_size']);
        $key = self::generate_key($options['signature_passphrase_id'], $this->signature_passphrases, $key_salt, $algorithm);

        $data = $this->encode($data, $algorithm, $key);

        return $data . $key_salt;
    }


    private function unsign_data($data, $options) {
        if (!array_key_exists($options['signature_algorithm_id'], $this->signature_algorithms)) {
            throw new Exception('Unknown signature algorithm id: ' . var_export($options['signature_algorithm_id'], TRUE));
        }

        $signature_algorithm = $this->signature_algorithms[$options['signature_algorithm_id']];

        $algorithm = self::get_algorithm_info($signature_algorithm);

        $key_salt = "";
        if ($algorithm['salt_size']) {
            $key_salt = substr($data, -$algorithm['salt_size']);
            $data = substr($data, 0, -$algorithm['salt_size']);
        }

        $key = self::generate_key($options['signature_passphrase_id'], $this->signature_passphrases, $key_salt, $algorithm);

        $data = $this->decode($data, $algorithm, $key);

        return $data;
    }


    public function encrypt_data($data, $options) {
        if (!array_key_exists($options['encryption_algorithm_id'], $this->encryption_algorithms)) {
            throw new Exception('Unknown encryption algorithm id: ' . var_export($options['encryption_algorithm_id'], TRUE));
        }

        $encryption_algorithm = $this->encryption_algorithms[$options['encryption_algorithm_id']];

        $algorithm = self::get_algorithm_info($encryption_algorithm);

        $key_salt = self::get_random_bytes($algorithm['salt_size']);
        $key = self::generate_key($options['encryption_passphrase_id'], $this->encryption_passphrases, $key_salt, $algorithm);

        $data = $this->encode($data, $algorithm, $key);

        return $data . $key_salt;
    }


    public function decrypt_data($data, $options) {
        if (!array_key_exists($options['encryption_algorithm_id'], $this->encryption_algorithms)) {
            throw new Exception('Unknown encryption algorithm id: ' . var_export($options['encryption_algorithm_id'], TRUE));
        }

        $encryption_algorithm = $this->encryption_algorithms[$options['encryption_algorithm_id']];

        $algorithm = self::get_algorithm_info($encryption_algorithm);

        $key_salt = "";
        if ($algorithm['salt_size']) {
            $key_salt = substr($data, -$algorithm['salt_size']);
            $data = substr($data, 0, -$algorithm['salt_size']);
        }

        $key = self::generate_key($options['encryption_passphrase_id'], $this->encryption_passphrases, $key_salt, $algorithm);

        $data = $this->decode($data, $algorithm, $key);

        return $data;
    }


    public function serialize_data($data, $options) {
        if (!array_key_exists($options['serialization_algorithm_id'], $this->serialization_algorithms)) {
            throw new Exception('Unknown serialization algorithm id: ' . var_export($options['serialization_algorithm_id'], TRUE));
        }

        $serialization_algorithm = $this->serialization_algorithms[$options['serialization_algorithm_id']];

        $algorithm = self::get_algorithm_info($serialization_algorithm);

        $data = $this->encode($data, $algorithm);

        return $data;
    }


    public function unserialize_data($data, $options) {
        if (!array_key_exists($options['serialization_algorithm_id'], $this->serialization_algorithms)) {
            throw new Exception('Unknown serialization algorithm id: ' . var_export($options['serialization_algorithm_id'], TRUE));
        }

        $serialization_algorithm = $this->serialization_algorithms[$options['serialization_algorithm_id']];

        $algorithm = self::get_algorithm_info($serialization_algorithm);

        $data = $this->decode($data, $algorithm);

        return $data;
    }


    public function compress_data($data, $options) {
        if (!array_key_exists($options['compression_algorithm_id'], $this->compression_algorithms)) {
            throw new Exception('Unknown compression algorithm id: ' . var_export($options['compression_algorithm_id'], TRUE));
        }

        $compression_algorithm = $this->compression_algorithms[$options['compression_algorithm_id']];

        $algorithm = self::get_algorithm_info($compression_algorithm);

        $compressed = $this->encode($data, $algorithm);

        if (strlen($compressed) < strlen($data)) {
            $data = $compressed;
        } else {
            $options['compression_algorithm_id'] = 0;
        }

        return $data;
    }


    public function decompress_data($data, $options) {
        if (!array_key_exists($options['compression_algorithm_id'], $this->compression_algorithms)) {
            throw new Exception('Unknown compression algorithm id: ' . var_export($options['compression_algorithm_id'], TRUE));
        }

        $compression_algorithm = $this->compression_algorithms[$options['compression_algorithm_id']];

        $algorithm = self::get_algorithm_info($compression_algorithm);

        $data = $this->decode($data, $algorithm);

        return $data;
    }


    private function remove_magic($data) {
        if ($this->magic === NULL) {
            return $data;
        }

        $magic_size = strlen($this->magic);
        $magic = substr($data, 0, $magic_size);
        if ($magic !== $this->magic) {
            throw new Exception('Invalid magic');
        }
        $data = substr($data, $magic_size);

        return $data;
    }


    private function add_magic($data) {
        if ($this->magic !== NULL) {
            return $this->magic . $data;
        }

        return $data;
    }


    private function add_header($data, $options) {
        $version_info = $this->get_version_info($options['version']);

        $flags = $options['flags'];

        $header_flags = "";
        foreach($version_info['flags'] as $flag) {
            $header_flags .= (string)(integer)($options['flags'][$flag]);
        }
        $header_flags = bindec($header_flags);

        $options['flags'] = $header_flags;

        $header = "";
        $header_info = $version_info['header'];
        foreach($header_info as $key) {
            $header .= pack($version_info['header_format'][key($header_info)], $options[$key]);
            next($header_info);
        }

        if (!empty($flags['timestamp'])) {
            $timestamp = time();
            $timestamp = self::pack_int_64($timestamp);
            $header .= $timestamp;
        }

        return $header . $data;
    }


    private function read_header($data) {
        $version = $this->read_version($data);
        $version_info = $this->get_version_info($version);
        $header_data = substr($data, 0, $version_info['header_size']);
        $header = unpack($version_info['header_format_unpack'], $header_data);
        $header = array_combine($version_info['header'], $header);

        $flags = explode("\r\n", chunk_split(sprintf("%08b", $header['flags']), 1), 8);
        $flags = array_combine($version_info['flags'], $flags);
        $header['flags'] = $flags;

        $timestamp = NULL;
        if (!empty($flags['timestamp'])) {
            $ts_start = $version_info['header_size'];
            $ts_end = $ts_start + $version_info['timestamp_size'];
            $timestamp_data = substr($data, $ts_start, $ts_end);
            $timestamp = self::unpack_int_64($timestamp_data);
        }
        $header['info'] = array('timestamp' => $timestamp);

        return $header;
    }


    private function remove_header($data, $options) {
        $version_info = $this->get_version_info($options['version']);

        $header_size = $version_info['header_size'];

        if (!empty($options['flags']['timestamp'])) {
            $header_size += $version_info['timestamp_size'];
        }

        $data = substr($data, $header_size);

        return $data;
    }


    private function read_version($data) {
        $version = ord($data[0]);

        if (!array_key_exists($version, self::$VERSIONS)) {
            throw new Exception('Version not defined: ' . var_export($version, TRUE));
        }

        return $version;
    }


    private function get_version_info($version) {
        return self::$VERSIONS[$version];
    }


    private function get_algorithm_info($algorithm_info) {
        if (!array_key_exists($algorithm_info['algorithm'], self::$ALGORITHMS)) {
            throw new Exception('Algorithm not supported: ' . var_export($algorithm_info['algorithm'], TRUE));
        }

        $algorithm = self::$ALGORITHMS[$algorithm_info['algorithm']];
        $algorithm_info = array_merge($algorithm_info, $algorithm);

        return $algorithm_info;
    }


    private static function generate_key($pass_id, $passphrases, $salt, $algorithm) {
        if (!array_key_exists($pass_id, $passphrases)) {
            throw new Exception('Passphrase not defined for id: ' . var_export($pass_id, TRUE));
        }

         $passphrase = $passphrases[$pass_id];

        if (strlen($passphrase) < 32) {
            throw new Exception('Passphrase less than 32 characters long');
        }

        if (function_exists("hash_pbkdf2")) {
            return hash_pbkdf2($algorithm['pbkdf2_algorithm'], $passphrase, $salt, $algorithm['pbkdf2_iterations'], $algorithm['key_size'], TRUE);
        } else {
            require_once(dirname(__FILE__) . '/pbkdf2/pbkdf2.php');

            return pbkdf2($algorithm['pbkdf2_algorithm'], $passphrase, $salt, $algorithm['pbkdf2_iterations'], $algorithm['key_size'], TRUE);
        }
    }


    private static function update_array($data, array $default_data, $replace_data = FALSE) {
        if (empty($data)) {
            return $default_data;
        }

        if (!is_array($data)) {
            throw new Exception('Value not array type');
        }
        if (count($data) > 255) {
            throw new Exception('More than 255 values defined');
        }
        foreach($data as $i => $v) {
            if (!is_integer($i)) {
                throw new Exception('Index not int type');
            }
            if ($i < 0 || $i > 255) {
                throw new Exception('Index value out of range');
            }
        }

        if (!$replace_data) {
            $data = $data + $default_data;
        }

        return $data;
    }


    private static function get_random_bytes($length) {
        /* Use mt_rand to generate $length random bytes */
        $data = '';
        for($i = 0; $i < $length; $i++) {
            $data .= chr(mt_rand(0, 255));
        }

        return $data;
    }


    private static function pack_int_64($int) {
        $left = 0xFFFFFFFF00000000; 
        $right = 0x00000000FFFFFFFF; 

        $int_left = ($int & $left) >> 32; 
        $int_right = $int & $right; 

        $int = pack('NN', $int_left, $int_right); 

        return $int;
    }


    private static function unpack_int_64($data) {
        $int = unpack('Nleft/Nright', $data);
        $int = ($int['left'] << 32) | $int['right'];

        return $int;
    }


    private static function is_equal($s1, $s2) {
        /*
         * Time independent compare; see e.g.
         * http://rdist.root.org/2010/01/07/timing-independent-array-comparison/
         */

        if (strlen($s1) != strlen($s2)) {
            return false;
        }

        $result = true;
        $length = strlen($s1);
        for ($i = 0; $i < $length; $i++) {
            $result &= ($s1[$i] == $s2[$i]);
        }
        return $result;
    }


    private static function urlsafe_b64_encode($string) {
        /*
         * URL safe base64 with trimmed padding (=).
         * PHP base64_decode ignores padding errors, some other languages don't,
         * in which case we should add padding before decoding.
         *
         */
        return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
    }


    private static function urlsafe_b64_decode($string) {
        /*
         * URL safe base64 decode with trimmed padding (=).
         * PHP base64_decode ignores padding errors, so we don't have to add
         * padding, but we could e.g.:
         *
         * $padding_num = strlen($string) % 4;
         * if ($padding_num != 0) {
         *   $padding_num = 4 - $padding_num;
         * }
         * $string = str_pad($string, strlen($string) + $padding_num, '=');
        */
        return base64_decode(strtr($string, '-_', '+/'));
    }


    private static function hmac_generate($data, $algorithm, $key) {
        if (in_array($algorithm['subtype'], array('sha256', 'sha384', 'sha512'), TRUE)) {
            return hash_hmac($algorithm['subtype'], $data, $key, TRUE);
        } else {
            throw new Exception('HMAC subtype not supported: ' . var_export($algorithm['subtype'], TRUE));
        }
    }


    private static function aes_encrypt($data, $algorithm, $key) {
        assert('is_string($data)');

        if (!function_exists("mcrypt_encrypt")) {
            throw new Exception("mcrypt php module not installed");
        }

        if ($algorithm['subtype'] === 'cbc') {
            $mode = MCRYPT_MODE_CBC;
        } else {
            throw new Exception("AES subtype not supported: " . var_export($algorithm['subtype'], TRUE));
        }

        $enc = MCRYPT_RIJNDAEL_128;

        $iv_size = $algorithm['iv_size'];
        $block_size = $iv_size;
        $include_iv = TRUE;

        if (isset($algorithm['iv'])) {
            if (strlen($algorithm['iv']) !== $iv_size) {
                throw new Exception("Invalid IV size");
            }
            $iv = $algorithm['iv'];
            $include_iv = FALSE;
        } else {
            $iv = self::get_random_bytes($iv_size);
        }

        $len = strlen($data);
        $numpad = $block_size - ($len % $block_size);
        $data = str_pad($data, $len + $numpad, chr($numpad));

        $data = mcrypt_encrypt($enc, $key, $data, $mode, $iv);

        if ($include_iv === TRUE) {
            return $iv . $data;
        }

        return $data;
    }


    private static function aes_decrypt($data, $algorithm, $key) {
        assert('is_string($data)');

        if (!function_exists("mcrypt_encrypt")) {
            throw new Exception("mcrypt php module not installed");
        }

        if ($algorithm['subtype'] === 'cbc') {
            $mode = MCRYPT_MODE_CBC;
        } else {
            throw new Exception("AES subtype not supported: " . var_export($algorithm['subtype'], TRUE));
        }

        $enc = MCRYPT_RIJNDAEL_128;

        $iv_size = $algorithm['iv_size'];

        if (isset($algorithm['iv'])) {
            $iv = $algorithm['iv'];
        } else {
            $iv = substr($data, 0, $iv_size);
            $data = substr($data, $iv_size);
        }

        $dec = mcrypt_decrypt($enc, $key, $data, $mode, $iv);

        $len = strlen($dec);
        $numpad = ord($dec[$len - 1]);
        $dec = substr($dec, 0, $len - $numpad);

        return $dec;
    }


    private static function zlib_compress($data, $algorithm) {
        if ($algorithm['subtype'] === 'deflate') {
            return gzdeflate($data, $algorithm['level']);
        } else {
            throw new Exception('Compression subtype not supported: ' . var_export($algorithm['subtype'], TRUE));
        }
    }


    private static function zlib_decompress($data, $algorithm) {
        if ($algorithm['subtype'] === 'deflate') {
            return gzinflate($data);
        } else {
            throw new Exception('Compression subtype not supported: ' . var_export($algorithm['subtype'], TRUE));
        }
    }
}
