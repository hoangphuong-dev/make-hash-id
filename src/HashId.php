<?php

namespace Hash;

use AllowDynamicProperties;
use Exception;

#[AllowDynamicProperties]
class HashId
{
    // Các giá trị hằng số cho việc mã hóa
    const MIN_ALPHABET_LENGTH = 10;
    const SEP_DIV = 3.5;
    const GUARD_DIV = 12;

    const E_ALPHABET_LENGTH = 'alphabet must contain at least %d unique characters';
    const E_ALPHABET_SPACE  = 'alphabet cannot contain spaces';

    // Thuộc tính để lưu trữ bảng chữ cái, ký tự phân cách và độ dài tối thiểu của hash
    private string $_alphabet = 'abcdefghijklmnpqrstuvwxyz123456789';
    private string $_seps = 'cfhistupCFHISTUP';
    private int $_min_hash_length = 0;
    private array $_math_functions = [];
    private int $_max_int_value = 1000000000;
    private int $_lower_max_int_value;
    private string $_salt;
    private string $_guards = '';

    /**
     * Constructor để khởi tạo các thuộc tính và kiểm tra tham số đầu vào
     *
     * @param string $salt Muối để trộn bảng chữ cái
     * @param int $min_hash_length Độ dài tối thiểu của hash
     * @param string $alphabet Bảng chữ cái sử dụng để mã hóa
     * @throws Exception Nếu bảng chữ cái không hợp lệ
     */
    public function __construct($salt = '', $min_hash_length = 0, $alphabet = '')
    {
        // Khởi tạo các hàm toán học nếu có
        $this->_math_functions = $this->_initMathFunctions();
        $this->_lower_max_int_value = $this->_max_int_value;
        if ($this->_math_functions) {
            $this->_max_int_value = PHP_INT_MAX;
        }

        // Thiết lập các thuộc tính từ các tham số đầu vào
        $this->_salt = $salt;
        if ((int)$min_hash_length > 0) {
            $this->_min_hash_length = (int)$min_hash_length;
        }

        if ($alphabet) {
            $this->_alphabet = implode('', array_unique(str_split($alphabet)));
        }

        // Kiểm tra tính hợp lệ của bảng chữ cái
        $this->_validateAlphabet();

        // Xử lý bảng chữ cái và các ký tự phân cách
        $alphabet_array = str_split($this->_alphabet);
        $seps_array = str_split($this->_seps);
        $this->_seps = implode('', array_intersect($alphabet_array, $seps_array));
        $this->_alphabet = implode('', array_diff($alphabet_array, $seps_array));
        $this->_seps = $this->_consistent_shuffle($this->_seps, $this->_salt);

        // Điều chỉnh các ký tự phân cách
        $this->_adjustSeps();
        // Trộn bảng chữ cái
        $this->_alphabet = $this->_consistent_shuffle($this->_alphabet, $this->_salt);
        // Điều chỉnh các ký tự bảo vệ
        $this->_adjustGuards();
    }

    /**
     * Mã hóa một hoặc nhiều số nguyên thành chuỗi hash
     *
     * @param int ...$numbers Các số nguyên cần mã hóa
     * @return string Chuỗi hash mã hóa
     */
    public function encode(...$numbers)
    {
        $ret = '';
        if (count($numbers) === 1 && is_array($numbers[0])) {
            $numbers = $numbers[0];
        }

        // Kiểm tra tính hợp lệ của các số nguyên đầu vào
        foreach ($numbers as $number) {
            if (!ctype_digit((string)$number) || $number < 0 || $number > $this->_max_int_value) {
                return '';
            }
        }

        return $this->_encode($numbers);
    }

    /**
     * Giải mã chuỗi hash thành một mảng các số nguyên
     *
     * @param string $hash Chuỗi hash cần giải mã
     * @return array Mảng các số nguyên sau khi giải mã
     */
    public function decode($hash): array
    {
        if (!$hash || !is_string($hash) || !trim($hash)) {
            return [];
        }

        return $this->_decode(trim($hash), $this->_alphabet);
    }

    /**
     * Mã hóa chuỗi hex thành chuỗi hash
     *
     * @param string $str Chuỗi hex cần mã hóa
     * @return string Chuỗi hash mã hóa
     */
    public function encode_hex($str)
    {
        if (!ctype_xdigit((string)$str)) {
            return '';
        }

        $numbers = array_map(fn ($number) => hexdec('1' . $number), explode(' ', trim(chunk_split($str, 12, ' '))));
        return $this->encode(...$numbers);
    }

    /**
     * Giải mã chuỗi hash thành chuỗi hex
     *
     * @param string $hash Chuỗi hash cần giải mã
     * @return string Chuỗi hex sau khi giải mã
     */
    public function decode_hex($hash): string
    {
        $numbers = $this->decode($hash);
        return implode('', array_map(fn ($number) => substr(dechex($number), 1), $numbers));
    }

    /**
     * Trả về giá trị tối đa cho phép của số nguyên
     *
     * @return int Giá trị tối đa của số nguyên
     */
    public function get_max_int_value()
    {
        return $this->_max_int_value;
    }

    /**
     * Mã hóa các số nguyên thành chuỗi hash
     *
     * @param array $numbers Mảng các số nguyên cần mã hóa
     * @return string Chuỗi hash mã hóa
     */
    private function _encode(array $numbers)
    {
        $alphabet = $this->_alphabet;
        $numbers_hash_int = array_sum(array_map(fn ($number, $i) => $number % ($i + 100), $numbers, array_keys($numbers)));
        $lottery = $ret = $alphabet[$numbers_hash_int % strlen($alphabet)];

        foreach ($numbers as $i => $number) {
            $alphabet = $this->_consistent_shuffle($alphabet, substr($lottery . $this->_salt . $alphabet, 0, strlen($alphabet)));
            $ret .= $last = $this->_hash($number, $alphabet);
            if ($i + 1 < count($numbers)) {
                $number %= (ord($last) + $i);
                $ret .= $this->_seps[$number % strlen($this->_seps)];
            }
        }

        return $this->_ensureMinLength($ret, $numbers_hash_int, $alphabet);
    }

    /**
     * Giải mã chuỗi hash thành mảng các số nguyên
     *
     * @param string $hash Chuỗi hash cần giải mã
     * @param string $alphabet Bảng chữ cái sử dụng để giải mã
     * @return array Mảng các số nguyên sau khi giải mã
     */
    private function _decode($hash, $alphabet): array
    {
        $hash_breakdown = str_replace(str_split($this->_guards), ' ', $hash);
        $hash_array = explode(' ', $hash_breakdown);
        $i = count($hash_array) == 3 || count($hash_array) == 2 ? 1 : 0;

        $hash_breakdown = $hash_array[$i] ?? '';
        if (!$hash_breakdown) {
            return [];
        }

        $lottery = $hash_breakdown[0];
        $hash_breakdown = substr($hash_breakdown, 1);
        $hash_array = explode(' ', str_replace(str_split($this->_seps), ' ', $hash_breakdown));

        $ret = [];
        foreach ($hash_array as $sub_hash) {
            $alphabet = $this->_consistent_shuffle($alphabet, substr($lottery . $this->_salt . $alphabet, 0, strlen($alphabet)));
            $ret[] = (int)$this->_unhash($sub_hash, $alphabet);
        }

        return $this->_encode($ret) === $hash ? $ret : [];
    }

    /**
     * Khởi tạo các hàm toán học để sử dụng trong mã hóa/giải mã
     *
     * @return array Mảng các hàm toán học
     */
    private function _initMathFunctions(): array
    {
        if (function_exists('gmp_add')) {
            return ['add' => 'gmp_add', 'div' => 'gmp_div', 'str' => 'gmp_strval'];
        } elseif (function_exists('bcadd')) {
            return ['add' => 'bcadd', 'div' => 'bcdiv', 'str' => 'strval'];
        }
        return [];
    }

    /**
     * Kiểm tra tính hợp lệ của bảng chữ cái
     *
     * @throws Exception Nếu bảng chữ cái không hợp lệ
     */
    private function _validateAlphabet()
    {
        if (strlen($this->_alphabet) < self::MIN_ALPHABET_LENGTH) {
            throw new Exception(sprintf(self::E_ALPHABET_LENGTH, self::MIN_ALPHABET_LENGTH));
        }
        if (strpos($this->_alphabet, ' ') !== false) {
            throw new Exception(self::E_ALPHABET_SPACE);
        }
    }

    /**
     * Điều chỉnh các ký tự phân cách nếu cần
     */
    private function _adjustSeps()
    {
        if (!$this->_seps || (strlen($this->_alphabet) / strlen($this->_seps)) > self::SEP_DIV) {
            $seps_length = (int)ceil(strlen($this->_alphabet) / self::SEP_DIV);
            if ($seps_length == 1) {
                $seps_length++;
            }

            if ($seps_length > strlen($this->_seps)) {
                $diff = $seps_length - strlen($this->_seps);
                $this->_seps .= substr($this->_alphabet, 0, $diff);
                $this->_alphabet = substr($this->_alphabet, $diff);
            } else {
                $this->_seps = substr($this->_seps, 0, $seps_length);
            }
        }
    }

    /**
     * Điều chỉnh các ký tự bảo vệ nếu cần
     */
    private function _adjustGuards()
    {
        $guard_count = (int)ceil(strlen($this->_alphabet) / self::GUARD_DIV);
        if (strlen($this->_alphabet) < 3) {
            $this->_guards = substr($this->_seps, 0, $guard_count);
            $this->_seps = substr($this->_seps, $guard_count);
        } else {
            $this->_guards = substr($this->_alphabet, 0, $guard_count);
            $this->_alphabet = substr($this->_alphabet, $guard_count);
        }
    }

    /**
     * Đảm bảo chuỗi hash có độ dài tối thiểu
     *
     * @param string $ret Chuỗi hash cần kiểm tra
     * @param int $numbers_hash_int Giá trị hash của các số
     * @param string $alphabet Bảng chữ cái sử dụng để mã hóa
     * @return string Chuỗi hash đã được điều chỉnh
     */
    private function _ensureMinLength(string $ret, int $numbers_hash_int, string $alphabet): string
    {
        if (strlen($ret) < $this->_min_hash_length) {
            $guard_index = ($numbers_hash_int + ord($ret[0])) % strlen($this->_guards);
            $guard = $this->_guards[$guard_index];
            $ret = $guard . $ret;

            if (strlen($ret) < $this->_min_hash_length) {
                $guard_index = ($numbers_hash_int + ord($ret[2])) % strlen($this->_guards);
                $guard = $this->_guards[$guard_index];
                $ret .= $guard;
            }
        }

        $half_length = (int)(strlen($alphabet) / 2);
        while (strlen($ret) < $this->_min_hash_length) {
            $alphabet = $this->_consistent_shuffle($alphabet, $alphabet);
            $ret = substr($alphabet, $half_length) . $ret . substr($alphabet, 0, $half_length);
            $excess = strlen($ret) - $this->_min_hash_length;
            if ($excess > 0) {
                $ret = substr($ret, $excess / 2, $this->_min_hash_length);
            }
        }

        return $ret;
    }

    /**
     * Trộn bảng chữ cái một cách nhất quán theo muối
     *
     * @param string $alphabet Bảng chữ cái cần trộn
     * @param string $salt Muối để trộn
     * @return string Bảng chữ cái đã được trộn
     */
    private function _consistent_shuffle(string $alphabet, string $salt): string
    {
        if (!strlen($salt)) {
            return $alphabet;
        }

        for ($i = strlen($alphabet) - 1, $v = 0, $p = 0; $i > 0; $i--, $v++) {
            $v %= strlen($salt);
            $p += $int = ord($salt[$v]);
            $j = ($int + $v + $p) % $i;
            [$alphabet[$i], $alphabet[$j]] = [$alphabet[$j], $alphabet[$i]];
        }

        return $alphabet;
    }

    /**
     * Mã hóa số nguyên thành chuỗi bằng bảng chữ cái
     *
     * @param int $input Số nguyên cần mã hóa
     * @param string $alphabet Bảng chữ cái sử dụng để mã hóa
     * @return string Chuỗi mã hóa
     */
    private function _hash(int $input, string $alphabet): string
    {
        $hash = '';
        $alphabet_length = strlen($alphabet);
        while ($input) {
            $hash = $alphabet[$input % $alphabet_length] . $hash;
            $input = $input > $this->_lower_max_int_value && $this->_math_functions
                ? $this->_math_functions['str']($this->_math_functions['div']($input, $alphabet_length))
                : (int)($input / $alphabet_length);
        }
        return $hash;
    }

    /**
     * Giải mã chuỗi thành số nguyên bằng bảng chữ cái
     *
     * @param string $input Chuỗi cần giải mã
     * @param string $alphabet Bảng chữ cái sử dụng để giải mã
     * @return int Số nguyên sau khi giải mã
     */
    private function _unhash(string $input, string $alphabet): int
    {
        $number = 0;
        if (!strlen($input) || !$alphabet) {
            return $number;
        }

        $alphabet_length = strlen($alphabet);
        foreach (str_split($input) as $i => $char) {
            $pos = strpos($alphabet, $char);
            $number = $this->_math_functions
                ? $this->_math_functions['str']($this->_math_functions['add']($number, $pos * pow($alphabet_length, (strlen($input) - $i - 1))))
                : $number + $pos * pow($alphabet_length, (strlen($input) - $i - 1));
        }

        return $number;
    }
}
