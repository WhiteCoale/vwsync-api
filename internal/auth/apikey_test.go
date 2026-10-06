package auth

import (
	"strings"
	"testing"
)

func TestGeneratedKeysAreLongRandomAndVerify(t *testing.T) {
	key, hash, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "vwsk_") || len(key) != 5+43 {
		t.Fatalf("unexpected key shape: %d characters", len(key))
	}
	if len(hash) != 64 || hash != HashKey(key) {
		t.Fatalf("hash does not belong to the key: %s", hash)
	}
	other, _, _ := GenerateKey()
	if other == key {
		t.Fatal("two keys are identical")
	}

	keys, err := ParseHashes(hash)
	if err != nil {
		t.Fatal(err)
	}
	if !keys.Verify(key) {
		t.Fatal("the generated key is rejected")
	}
	for _, bad := range []string{"", other, key + " ", " " + key, strings.ToUpper(key), key[:len(key)-1], "vwsk_"} {
		if keys.Verify(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestSeveralKeysAreValidAtOnceForRotation(t *testing.T) {
	oldKey, oldHash, _ := GenerateKey()
	newKey, newHash, _ := GenerateKey()
	third, _, _ := GenerateKey()

	keys, err := ParseHashes(" " + oldHash + " , " + newHash + ",")
	if err != nil {
		t.Fatal(err)
	}
	if !keys.Verify(oldKey) || !keys.Verify(newKey) {
		t.Fatal("both configured keys must work during a rotation")
	}
	if keys.Verify(third) {
		t.Fatal("a key that is not configured was accepted")
	}

	onlyNew, _ := ParseHashes(newHash)
	if onlyNew.Verify(oldKey) {
		t.Fatal("after the old hash is removed the old key must stop working")
	}
}

func TestParseHashesRejectsBadInput(t *testing.T) {
	_, good, _ := GenerateKey()
	for name, in := range map[string]string{
		"empty":             "",
		"only separators":   " , ,",
		"not hex":           strings.Repeat("z", 64),
		"too short":         good[:63],
		"too long":          good + "0",
		"the key itself":    "vwsk_" + strings.Repeat("A", 43),
		"one good, one bad": good + ",nonsense",
	} {
		if _, err := ParseHashes(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestErrorsNeverEchoALongValue(t *testing.T) {
	secretLooking := "vwsk_" + strings.Repeat("S", 43)
	_, err := ParseHashes(secretLooking)
	if err == nil || strings.Contains(err.Error(), secretLooking) {
		t.Fatalf("the error repeats the value it was given: %v", err)
	}
}
