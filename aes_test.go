package aes

import (
	"bytes"
	"testing"
)

var stringifyTestCases = []struct {
	buff []byte
	str  string
}{
	{[]byte("a"), "YQ=="},
	{[]byte("hello"), "aGVsbG8="},
	{[]byte("this is a test"), "dGhpcyBpcyBhIHRlc3Q="},
	{[]byte("a```?><:}{|+_)(*&^%$#@!~`1234567890-=[];,/"), "YWBgYD8+PDp9e3wrXykoKiZeJSQjQCF+YDEyMzQ1Njc4OTAtPVtdOywv"},
}

func TestStringify(t *testing.T) {
	for _, testCase := range stringifyTestCases {
		answer := stringify(testCase.buff)
		if answer != testCase.str {
			t.Errorf("ERROR: For %v, expected %v, got %v", string(testCase.buff), testCase.str, answer)
		}
	}
}

func TestDestringify(t *testing.T) {
	for _, testCase := range stringifyTestCases {
		answer := destringify(testCase.str)
		if !bytes.Equal(answer, testCase.buff) {
			t.Errorf("ERROR: For %v, expected %v, got %v", testCase.str, testCase.buff, answer)
		}
	}
}

func TestMakeKey(t *testing.T) {
	testCases := []string{
		"a",
		"abc",
		"1234567890123456789012",
		"123456789012345678901234567890",
	}

	for _, testCase := range testCases {
		answer := makeKey(testCase)
		if len(answer) != 32 {
			t.Errorf("ERROR: For %v, expected 32, got %v", testCase, len(answer))
		}
	}
}

func TestEncrypt(t *testing.T) {
	var testCases = []struct {
		plaintext  string
		passphrase string
	}{
		{"foo", "bar"},
		{"adfs", "1234"},
		{"1234567890qwertyuiop", "!@#$%^&*()_"},
	}

	for _, testCase := range testCases {
		ciphertext := Encrypt(testCase.plaintext, testCase.passphrase)
		answer := Decrypt(ciphertext, testCase.passphrase)
		if answer != testCase.plaintext {
			t.Errorf("ERROR: For %v, got %v", testCase.plaintext, answer)
		}
	}
}

func TestDecrypt(t *testing.T) {
	testCases := []struct {
		ciphertext string
		passphrase string
		expected   string
	}{
		{"hlwjlfFMLUIWbbjyphbr4b1mbCsGYS3Ciy4gXvSnZg==", "foo", "bar"},
		{"vJ5fbgmTTPDc+ebBYbjaCq7JjOQWSy10T3JyC3wfF4Xp0UoEaq40", "bites", "rattlesnake"},
		{"R8DVyNffT7wwsuHFnP03gEz6PuafTMCn52uJoDJaljQ2hica/D+VGPXQXg==", "good men", "Now is the time"},
		{"tFcAmq1O0Ze0yw879U4PTNZ8lMxUxZWhSVZ758BmRD+RVWBh9fwQ", "<>?,./", "!@#$%^&*()_"},
	}

	for _, testCase := range testCases {
		answer := Decrypt(testCase.ciphertext, testCase.passphrase)
		if answer != testCase.expected {
			t.Errorf("ERROR: For %v, expected %v, got %v", testCase.ciphertext, testCase.expected, answer)
		}
	}
}
