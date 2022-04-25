package sha1dc

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestBasicHash(t *testing.T) {
	data := []byte("abc123\r\n")
	out, err := writeAllAndFinalize(data)
	if err != nil {
		t.Fatal(err)
	}
	outHex := hex.EncodeToString(out)
	expected := "893b3c49b8f10d8b72e0c021bce0cf3fa791773f"
	if outHex != expected {
		t.Fatalf("expected %s, got %s", expected, outHex)
	}
}

func TestHashCollisions(t *testing.T) {
	t.Run("Shattered1", func(t *testing.T) {
		testHashCollisionsInner(t, "./fixtures/shattered-1.pdf")
	})
	t.Run("Shattered2", func(t *testing.T) {
		testHashCollisionsInner(t, "./fixtures/shattered-2.pdf")
	})
	t.Run("Shambles1", func(t *testing.T) {
		testHashCollisionsInner(t, "./fixtures/shambles-messageA")
	})
	t.Run("Shambles2", func(t *testing.T) {
		testHashCollisionsInner(t, "./fixtures/shambles-messageB")
	})
}

func testHashCollisionsInner(t *testing.T, filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	_, err = writeAllAndFinalize(data)
	if err != ErrSHA1Collision {
		t.Fatalf("expected collision error got %v", err)
	}
}

func writeAllAndFinalize(data []byte) ([]byte, error) {
	d := New()
	n, err := d.Write(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, fmt.Errorf("expected %d bytes written, got %d", len(data), n)
	}
	out, err := d.Finalize()
	if err != nil {
		return nil, err
	}
	return out, nil
}