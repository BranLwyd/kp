package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"
)

var (
	kdbxFile  = flag.String("file", "foo.kdbx", "kdbx file to read")
	printBody = flag.Bool("print_body", true, "If set, print the data on successful decryption")
)

type headerFieldType uint8
type compressionFormat uint32
type innerRandomStreamType uint32

const (
	// Expected signature values.
	expectedSig1 = 0x9AA2D903
	expectedSig2 = 0xB54BFB67

	// Header field types.
	endOfHeader         headerFieldType = 0
	comment             headerFieldType = 1
	cipherID            headerFieldType = 2
	compressionFlags    headerFieldType = 3
	masterSeed          headerFieldType = 4
	transformSeed       headerFieldType = 5
	transformRounds     headerFieldType = 6
	encryptionIV        headerFieldType = 7
	protectedStreamKey  headerFieldType = 8
	streamStartBytes    headerFieldType = 9
	innerRandomStreamID headerFieldType = 10

	// Compression formats.
	noCompression   compressionFormat = 0
	gzipCompression compressionFormat = 1

	// Inner random stream types.
	noInner      innerRandomStreamType = 0
	arc4Inner    innerRandomStreamType = 1
	salsa20Inner innerRandomStreamType = 2
)

var (
	aesCipherID, _ = hex.DecodeString("31c1f2e6bf714350be5805216afc5aff")
)

type headerData struct {
	majorVersion        uint16
	minorVersion        uint16
	compressionFormat   compressionFormat
	masterSeed          []byte
	transformSeed       []byte
	transformRounds     uint64
	encryptionIV        []byte
	protectedStreamKey  []byte
	streamStartBytes    []byte
	innerRandomStreamID innerRandomStreamType
}

type Credentials struct {
	Passphrase []byte
	KeyFile    []byte
}

var headerFieldHandlers = map[headerFieldType]func(*headerData, []byte) error{
	endOfHeader: func(_ *headerData, _ []byte) error { return nil },
	comment:     func(_ *headerData, _ []byte) error { return nil },

	cipherID: func(_ *headerData, val []byte) error {
		if bytes.Compare(val, aesCipherID) != 0 {
			return errors.New("unknown cipher ID")
		}
		return nil
	},

	compressionFlags: func(hdr *headerData, val []byte) error {
		if len(val) != 4 {
			return fmt.Errorf("unexpected compression flags length (%d != 4)", len(val))
		}
		if err := binary.Read(bytes.NewReader(val), binary.LittleEndian, &hdr.compressionFormat); err != nil {
			return fmt.Errorf("error parsing compression flags: %v", err)
		}
		if hdr.compressionFormat > gzipCompression {
			return fmt.Errorf("unexpected compression format (%d)", hdr.compressionFormat)
		}
		return nil
	},

	masterSeed: func(hdr *headerData, val []byte) error {
		if len(val) != 32 {
			return fmt.Errorf("unexpected master seed length (%d != 32)", len(val))
		}
		hdr.masterSeed = val
		return nil
	},

	transformSeed: func(hdr *headerData, val []byte) error {
		if len(val) != 32 {
			return fmt.Errorf("unexpected transform seed length (%d != 32)", len(val))
		}
		hdr.transformSeed = val
		return nil
	},

	transformRounds: func(hdr *headerData, val []byte) error {
		if len(val) != 8 {
			return fmt.Errorf("unexpected transform rounds length (%d != 8)", len(val))
		}
		if err := binary.Read(bytes.NewReader(val), binary.LittleEndian, &hdr.transformRounds); err != nil {
			return fmt.Errorf("could not parse transform rounds: %v", err)
		}
		return nil
	},

	encryptionIV: func(hdr *headerData, val []byte) error {
		hdr.encryptionIV = val
		return nil
	},

	protectedStreamKey: func(hdr *headerData, val []byte) error {
		hdr.protectedStreamKey = val
		return nil
	},

	streamStartBytes: func(hdr *headerData, val []byte) error {
		if len(val) != 32 {
			return fmt.Errorf("unexpected stream start bytes length (%d != 32)", len(val))
		}
		hdr.streamStartBytes = val
		return nil
	},

	innerRandomStreamID: func(hdr *headerData, val []byte) error {
		if len(val) != 4 {
			return fmt.Errorf("unexpected inner random stream ID length (%d != 4)", len(val))
		}
		if err := binary.Read(bytes.NewReader(val), binary.LittleEndian, &hdr.innerRandomStreamID); err != nil {
			return fmt.Errorf("could not parse inner random stream ID: %v", err)
		}
		if hdr.innerRandomStreamID > salsa20Inner {
			return fmt.Errorf("unexpected inner random stream ID (%d)", hdr.innerRandomStreamID)
		}
		return nil
	},
}

func read(r io.Reader, buf []byte) error {
	for len(buf) > 0 {
		n, err := r.Read(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

func readHeader(r io.Reader) (*headerData, error) {
	// Signature & file version.
	hdr := &headerData{}
	var sig1, sig2 uint32
	if err := binary.Read(r, binary.LittleEndian, &sig1); err != nil {
		return nil, fmt.Errorf("error parsing header: %v", err)
	}
	// TODO(bran): handle alternate second signatures (kdbx pre-release)
	if err := binary.Read(r, binary.LittleEndian, &sig2); err != nil {
		return nil, fmt.Errorf("error parsing header: %v", err)
	}
	if sig1 != expectedSig1 || sig2 != expectedSig2 {
		return nil, errors.New("error parsing header: signature mismatch")
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr.minorVersion); err != nil {
		return nil, fmt.Errorf("error parsing header: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr.majorVersion); err != nil {
		return nil, fmt.Errorf("error parsing header: %v", err)
	}
	// TODO(bran): validate version

	// Header fields.
	handlers := make(map[headerFieldType]func(*headerData, []byte) error)
	for typ, hfh := range headerFieldHandlers {
		handlers[typ] = hfh
	}
	typ := comment
	for typ != endOfHeader {
		if err := binary.Read(r, binary.LittleEndian, &typ); err != nil {
			return nil, fmt.Errorf("error parsing header: %v", err)
		}
		var valLen uint16
		if err := binary.Read(r, binary.LittleEndian, &valLen); err != nil {
			return nil, fmt.Errorf("error parsing header: %v", err)
		}
		val := make([]byte, valLen)
		if err := read(r, val); err != nil {
			return nil, fmt.Errorf("error parsing header: %v", err)
		}

		hfh, ok := handlers[typ]
		if !ok {
			return nil, fmt.Errorf("error parsing header: unexpected or duplicate header field type (%d)", typ)
		}
		if err := hfh(hdr, val); err != nil {
			return nil, fmt.Errorf("error parsing header: %v", err)
		}
		if typ != comment {
			delete(handlers, typ)
		}
	}
	for typ, _ := range handlers {
		if typ != comment {
			return nil, fmt.Errorf("error parsing header: missing header field (%d)", typ)
		}
	}

	return hdr, nil
}

func hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func itercrypt(blk cipher.Block, rounds uint64, data []byte) chan struct{} {
	doneCh := make(chan struct{})
	go func() {
		for i := uint64(0); i < rounds; i++ {
			blk.Encrypt(data, data)
		}
		close(doneCh)
	}()
	return doneCh
}

func deriveMasterKey(hdr *headerData, creds *Credentials) ([]byte, error) {
	// Create cipher.
	blk, err := aes.NewCipher(hdr.transformSeed)
	if err != nil {
		return nil, fmt.Errorf("could not derive master key: %v", err)
	}

	// Compute composite key from credentials.
	var compositeKey []byte
	if creds.Passphrase != nil {
		compositeKey = append(compositeKey, hash(creds.Passphrase)...)
	}
	if creds.KeyFile != nil {
		compositeKey = append(compositeKey, hash(creds.KeyFile)...)
	}

	// Compute transformed key from composite key.
	transformedKey := hash(compositeKey)
	done1 := itercrypt(blk, hdr.transformRounds, transformedKey[0:16])
	done2 := itercrypt(blk, hdr.transformRounds, transformedKey[16:32])
	<-done1
	<-done2

	return hash(append(hdr.masterSeed, hash(transformedKey)...)), nil
}

func parseBlocks(r io.Reader, decompress bool) ([]byte, error) {
	// Read blocks.
	blks := make(map[uint32][]byte)
	for {
		var blkID, blkSize uint32
		var blkHash [sha256.Size]byte

		if err := binary.Read(r, binary.LittleEndian, &blkID); err != nil {
			return nil, fmt.Errorf("could not parse body: %v", err)
		}
		if err := read(r, blkHash[:]); err != nil {
			return nil, fmt.Errorf("could not parse body: %v", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &blkSize); err != nil {
			return nil, fmt.Errorf("could not parse body: %v", err)
		}
		blkData := make([]byte, blkSize)
		if err := read(r, blkData); err != nil {
			return nil, fmt.Errorf("could not parse body: %v", err)
		}

		if blkSize == 0 {
			break
		}

		if blkHash != sha256.Sum256(blkData) {
			return nil, errors.New("could not parse body: block hash mismatch")
		}
		if decompress {
			if err := func() error {
				gr, err := gzip.NewReader(bytes.NewReader(blkData))
				if err != nil {
					return fmt.Errorf("could not parse body: %v", err)
				}
				defer gr.Close()
				d, err := ioutil.ReadAll(gr)
				if err != nil {
					return fmt.Errorf("could not parse body: %v", err)
				}
				blkData = d
				return nil
			}(); err != nil {
				return nil, err
			}
		}

		blks[blkID] = blkData
	}

	// Reconstruct data from blocks.
	var data []byte

	i := uint32(0)
	for {
		blkData, ok := blks[i]
		if !ok {
			break
		}
		data = append(data, blkData...)
		delete(blks, i)
		i++
	}
	if len(blks) != 0 {
		return nil, fmt.Errorf("could not parse block: missing block ID %d", i)
	}
	return data, nil
}

func readBody(r io.Reader, hdr *headerData, creds *Credentials) ([]byte, error) {
	// Read & decrypt body bytes.
	masterKey, err := deriveMasterKey(hdr, creds)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt body: %v", err)
	}
	blk, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt body: %v", err)
	}
	cbc := cipher.NewCBCDecrypter(blk, hdr.encryptionIV)
	bodyBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt body: %v", err)
	}
	cbc.CryptBlocks(bodyBytes, bodyBytes)

	// Check stream start bytes.
	if len(bodyBytes) < 32 {
		return nil, fmt.Errorf("could not decrypt body: missing start bytes")
	}
	if bytes.Compare(hdr.streamStartBytes, bodyBytes[:32]) != 0 {
		return nil, errors.New("invalid credentials or corrupt database")
	}
	bodyBytes = bodyBytes[32:]

	return parseBlocks(bytes.NewReader(bodyBytes), hdr.compressionFormat == gzipCompression)
}

func main() {
	flag.Parse()

	// Read file content.
	kdbx, err := os.Open(*kdbxFile)
	if err != nil {
		log.Fatalf("Could not open KeePass file: %v", err)
	}
	defer kdbx.Close()

	// Parse headers.
	hdr, err := readHeader(kdbx)
	if err != nil {
		log.Fatalf("Could not parse KeePass file: %v", err)
	}

	// Get passphrase and parse body.
	fmt.Print("Enter passphrase (NOT HIDDEN): ")
	rdr := bufio.NewReader(os.Stdin)
	passphrase, err := rdr.ReadSlice('\n')
	if err != nil {
		log.Fatalf("Could not get passphrase: %v", err)
	}
	passphrase = bytes.TrimSuffix(passphrase, []byte{'\n'})
	start := time.Now()
	body, err := readBody(kdbx, hdr, &Credentials{Passphrase: passphrase})
	if err != nil {
		log.Fatalf("Could not read body: %v", err)
	}
	end := time.Now()
	log.Printf("Total time to parse body: %v\n", end.Sub(start))
	if *printBody {
		fmt.Printf("%s\n", body)
	}
}
