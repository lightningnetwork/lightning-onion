package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/urfave/cli"
)

const (
	defaultHopDataPath = "cmd/example-data/hop-data.json"
	defaultOnionPath   = "cmd/example-data/onion.json"
)

// main implements a simple command line utility that can be used in order to
// either generate a fresh mix-header or decode and fully process an existing
// one given a private key.
func main() {
	app := cli.NewApp()
	app.Name = "sphinx-cli"
	app.Commands = []cli.Command{
		{
			Name: "genkeys",
			Usage: "A helper function to generate a random new " +
				"private-public key pair.",
			Action: genKeys,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "priv",
					Usage: "An optional flag to provide " +
						"a private key. In this " +
						"case, this command just " +
						"calculates and prints the " +
						"associated public key",
				},
			},
		},
		{
			Name: "nextephemeral",
			Usage: "A helper to compute the next ephemeral key " +
				"given the current ephemeral key and a " +
				"private key",
			Action: nextEphemeral,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "priv",
					Required: true,
				},
				cli.StringFlag{
					Name:     "pub",
					Required: true,
				},
			},
		},
		{
			Name:   "generate",
			Usage:  "Build a new onion.",
			Action: generate,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "file",
					Usage: "Path to json file containing " +
						"the session key and hops " +
						"data.",
					Value: defaultHopDataPath,
				},
			},
		},
		{
			Name:   "peel",
			Usage:  "Peel the onion.",
			Action: peel,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "file",
					Usage: "Path to json file containing " +
						"the onion to decode along " +
						"with the session key and " +
						"associated data.",
					Value: defaultOnionPath,
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}

func genKeys(cli *cli.Context) error {
	var (
		priv *btcec.PrivateKey
		pub  *btcec.PublicKey
		err  error
	)
	if privKeyStr := cli.String("priv"); privKeyStr != "" {
		privBytes, err := hex.DecodeString(privKeyStr)
		if err != nil {
			return err
		}
		priv, pub = btcec.PrivKeyFromBytes(privBytes)

	} else {
		priv, err = btcec.NewPrivateKey()
		if err != nil {
			return err
		}

		pub = priv.PubKey()
	}

	fmt.Printf("Private Key: %x\nPublic Key: %x\n", priv.Serialize(),
		pub.SerializeCompressed())

	return nil
}

type pathData struct {
	SessionKey     string    `json:"session_key"`
	AssociatedData string    `json:"associated_data"`
	Hops           []hopData `json:"hops"`
}

type hopData struct {
	PublicKey string `json:"pubkey"`
	Payload   string `json:"payload"`
}

func parsePathData(data pathData) (*sphinx.PaymentPath, *btcec.PrivateKey,
	[]byte, error) {

	sessionKeyBytes, err := hex.DecodeString(data.SessionKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to decode the "+
			"sessionKey %v: %v", data.SessionKey, err)
	}

	if len(sessionKeyBytes) != 32 {
		return nil, nil, nil, fmt.Errorf("session priv key must be " +
			"32 bytes long")
	}

	sessionKey, _ := btcec.PrivKeyFromBytes(sessionKeyBytes)

	assocData, err := hex.DecodeString(data.AssociatedData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to decode the "+
			"associate data %v: %v", data.AssociatedData, err)
	}

	var path sphinx.PaymentPath
	for i, hop := range data.Hops {
		binKey, err := hex.DecodeString(hop.PublicKey)
		if err != nil {
			return nil, nil, nil, err
		}

		pubkey, err := btcec.ParsePubKey(binKey)
		if err != nil {
			return nil, nil, nil, err
		}

		path[i].NodePub = *pubkey

		payload, err := hex.DecodeString(hop.Payload)
		if err != nil {
			return nil, nil, nil, err
		}

		hopPayload, err := sphinx.NewTLVHopPayload(payload)
		if err != nil {
			return nil, nil, nil, err
		}

		path[i].HopPayload = hopPayload
	}

	return &path, sessionKey, assocData, nil
}

func generate(ctx *cli.Context) error {
	file := ctx.String("file")
	jsonSpec, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("unable to read JSON onion spec from file "+
			"%v: %v", file, err)
	}

	var spec pathData
	if err := json.Unmarshal(jsonSpec, &spec); err != nil {
		return fmt.Errorf("unable to peel JSON onion spec: %v", err)
	}

	path, sessionKey, assocData, err := parsePathData(spec)
	if err != nil {
		return fmt.Errorf("could not peel onion spec: %v", err)
	}

	msg, err := sphinx.NewOnionPacket(
		path, sessionKey, assocData, sphinx.DeterministicPacketFiller,
	)
	if err != nil {
		return fmt.Errorf("error creating message: %v", err)
	}

	w := bytes.NewBuffer([]byte{})
	err = msg.Encode(w)
	if err != nil {
		return fmt.Errorf("error serializing message: %v", err)
	}

	fmt.Printf("%x\n", w.Bytes())
	return nil
}

type onionInfo struct {
	SessionKey     string `json:"session_key"`
	AssociatedData string `json:"associated_data"`
	BlindingPoint  string `json:"blinding_point"`
	Onion          string `json:"onion"`
}

func parseOnionInfo(info *onionInfo) (*sphinx.OnionPacket, *btcec.PrivateKey,
	[]byte, *btcec.PublicKey, error) {

	sessionKeyBytes, err := hex.DecodeString(info.SessionKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("unable to decode the "+
			"sessionKey %v: %v", info.SessionKey, err)
	}

	if len(sessionKeyBytes) != 32 {
		return nil, nil, nil, nil, fmt.Errorf("session priv key must " +
			"be 32 bytes long")
	}

	sessionKey, _ := btcec.PrivKeyFromBytes(sessionKeyBytes)

	assocData, err := hex.DecodeString(info.AssociatedData)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("unable to decode the "+
			"associate data %v: %v", info.AssociatedData, err)
	}

	onion, err := hex.DecodeString(info.Onion)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("unable to decode the "+
			"onion %v: %v", info.Onion, err)
	}

	var packet sphinx.OnionPacket
	err = packet.Decode(bytes.NewBuffer(onion))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var blindingPoint *btcec.PublicKey
	if info.BlindingPoint != "" {
		bpBytes, err := hex.DecodeString(info.BlindingPoint)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		blindingPoint, err = btcec.ParsePubKey(bpBytes)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	return &packet, sessionKey, assocData, blindingPoint, nil
}

func peel(ctx *cli.Context) error {
	file := ctx.String("file")
	jsonSpec, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("unable to read JSON onion spec from file "+
			"%v: %v", file, err)
	}

	var info onionInfo
	if err := json.Unmarshal(jsonSpec, &info); err != nil {
		return err
	}

	packet, sessionKey, assocData, blindingPoint, err := parseOnionInfo(
		&info,
	)
	if err != nil {
		return err
	}

	s := sphinx.NewRouter(
		&sphinx.PrivKeyECDH{PrivKey: sessionKey},
		&chaincfg.TestNet3Params, sphinx.NewMemoryReplayLog(),
	)
	s.Start()
	defer s.Stop()

	p, err := s.ProcessOnionPacket(
		packet, assocData, 10, sphinx.WithBlindingPoint(blindingPoint),
	)
	if err != nil {
		return err
	}

	w := bytes.NewBuffer([]byte{})
	if err = p.NextPacket.Encode(w); err != nil {
		return fmt.Errorf("error serializing message: %v", err)
	}

	fmt.Printf("%x\n", w.Bytes())

	return nil
}

func nextEphemeral(ctx *cli.Context) error {
	privKeyByte, err := hex.DecodeString(ctx.String("priv"))
	if err != nil {
		return err
	}
	if len(privKeyByte) != 32 {
		return fmt.Errorf("private key must be 32 bytes")
	}

	privKey, _ := btcec.PrivKeyFromBytes(privKeyByte)

	pubKeyBytes, err := hex.DecodeString(ctx.String("pub"))
	if err != nil {
		return err
	}

	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return err
	}

	nextBlindedKey, err := sphinx.NextEphemeral(
		&sphinx.PrivKeyECDH{PrivKey: privKey}, pubKey,
	)
	if err != nil {
		return err
	}

	fmt.Printf("%x\n", nextBlindedKey.SerializeCompressed())

	return nil
}
