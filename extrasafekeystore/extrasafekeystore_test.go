package extrasafekeystore

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestCreatePrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{
			name:    "test_different_keys",
			want:    "76d2ac1f534c5bfd6f66437b5fd24e5f7d1890589263be804e4e22d4c5e926a3",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreatePrivateKey()
			privateKeyHex := privateKeyHex(got)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreatePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reflect.DeepEqual(privateKeyHex, tt.want) {
				t.Errorf("CreatePrivateKey() got = %v, want %v", privateKeyHex, tt.want)
			}
		})
	}
}

func TestCreatePrivateKeyFromMnemonic(t *testing.T) {
	type args struct {
		words string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "test_ok",
			args:    args{words: "inflict race essay know royal crew deer seed sign evolve sure heart"},
			want:    "2e24e7d81dfa3cdfed65e8c0d98cc97fc6524d9eb2c61cae7a23ee9ecafa0c47",
			wantErr: false,
		},
		{
			name:    "test_missing_word",
			args:    args{words: "ability cheese vague ski public funny desert view either always tumble"},
			want:    "",
			wantErr: true,
		},
		{
			name:    "test_weak_entropy",
			args:    args{words: "inflict race essay know royal crew deer seed sign evolve sure accident"},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreatePrivateKeyFromMnemonic(tt.args.words)
			privateKeyHex := privateKeyHex(got)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreatePrivateKeyFromMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(privateKeyHex, tt.want) {
				t.Errorf("CreatePrivateKeyFromMnemonic() got = %v, want %v", privateKeyHex, tt.want)
			}
		})
	}
}

func TestStoreWithAES256(t *testing.T) {
	dir := tmpDir(t)
	defer os.RemoveAll(dir)

	type args struct {
		privateKey string
		passphrase string
	}
	tests := []struct {
		name        string
		strenght    int
		args        args
		wantErr     bool
		wantCipher  string
		wantScryptN int
	}{
		{
			name:     "test_256",
			strenght: 256,
			args: args{
				privateKey: "2e24e7d81dfa3cdfed65e8c0d98cc97fc6524d9eb2c61cae7a23ee9ecafa0c47",
				passphrase: "cantami.o.diva.del.pelide",
			},
			wantErr:     false,
			wantCipher:  "aes-256-ctr",
			wantScryptN: 1048576,
		},
		{
			name:     "test_128",
			strenght: 128,
			args: args{
				privateKey: "76d2ac1f534c5bfd6f66437b5fd24e5f7d1890589263be804e4e22d4c5e926a3",
				passphrase: "cantami.o.diva.del.pelide",
			},
			wantErr:     false,
			wantCipher:  "aes-128-ctr",
			wantScryptN: 262144,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := crypto.HexToECDSA(tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("StoreWithAES256() CreatePrivateKeyFromMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var path string
			switch tt.strenght {
			case 256:
				path, err = StoreWithAES256(dir, privateKey, tt.args.passphrase)
			case 128:
				path, err = StoreWithDefault(dir, privateKey, tt.args.passphrase)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("StoreWithAES256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			_, err = os.Stat(path)
			if os.IsNotExist(err) {
				t.Errorf("StoreWithAES256() got = %v, file does not exist", path)
			}
			keyjson, err := ioutil.ReadFile(path)
			if err != nil {
				t.Errorf("StoreWithAES256() got = %v, file is corrupt, error %v", path, err)
			}
			m := make(map[string]interface{})
			if err := json.Unmarshal(keyjson, &m); err != nil {
				t.Errorf("StoreWithAES256() got = %v, Unmarshal error %v", path, err)
			}
			crypto := m["crypto"].(map[string]interface{})
			cipher := crypto["cipher"].(string)
			if cipher != tt.wantCipher {
				t.Errorf("StoreWithAES256() Cipher got = %v, wanted = %v", crypto["cipher"], tt.wantCipher)
			}
			kdfparams := crypto["kdfparams"].(map[string]interface{})
			scryptN := int(kdfparams["n"].(float64))
			if scryptN != tt.wantScryptN {
				t.Errorf("StoreWithAES256() ScryptN got = %v, wanted = %v", kdfparams["n"], tt.wantScryptN)
			}

		})
	}
}

func tmpDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", "eth-keystore-test")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
