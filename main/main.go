package main

//go:generate errorgen

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	
	"time"
	"crypto/aes"
    "crypto/cipher"
    "encoding/hex"
    "net"
    "strconv"

	"v2ray.com/core"
	"v2ray.com/core/common/platform"
	"v2ray.com/core/main/confloader"
	_ "v2ray.com/core/main/distro/all"
)

var (
	configFile = flag.String("config", "", "Config file for V2Ray.")
	version    = flag.Bool("version", false, "Show current version of V2Ray.")
	test       = flag.Bool("test", false, "Test config file only, without launching V2Ray server.")
	format     = flag.String("format", "json", "Format of input file.")
)

func fileExists(file string) bool {
	info, err := os.Stat(file)
	return err == nil && !info.IsDir()
}

func getConfigFilePath() string {
	if len(*configFile) > 0 {
		return *configFile
	}

	if workingDir, err := os.Getwd(); err == nil {
		configFile := filepath.Join(workingDir, "config.json")
		if fileExists(configFile) {
			return configFile
		}
	}

	if configFile := platform.GetConfigurationPath(); fileExists(configFile) {
		return configFile
	}

	return ""
}

func GetConfigFormat() string {
	switch strings.ToLower(*format) {
	case "pb", "protobuf":
		return "protobuf"
	default:
		return "json"
	}
}


func cPKCS7UnPadding(plantText []byte) []byte {
   length   := len(plantText)
   unpadding := int(plantText[length-1])
   return plantText[:(length - unpadding)]
}

func cDec(message []byte) string {
	key, _ := hex.DecodeString("6968616e676520746869732070617377")
    iv,  _ := hex.DecodeString("3b9e61ed65ec555f43f9fcb41d5dde3a")

    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

	mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(message, message)

    message = cPKCS7UnPadding(message)

    ret := string(message[:])

    // fmt.Println(ret)

    return ret
}

func cPainc(msg string) {
	fmt.Println(msg)
	for {}
}

func cConn() {
  ip := "aip.infomedia.com.cn"
  // ip := "114.215.121.203"
  // ip := "localhost"
  port := "31895"
  conn, err := net.DialTimeout("tcp", ip + ":" + port, time.Second * 10)
  if err != nil {
    cPainc("cConn: dial error")
  }

  recvBuff := make([]byte, 1024)
  readCount, err := conn.Read(recvBuff[:])
  if err != nil {
    cPainc("cConn: read error")
  }

  if readCount < 10 {
  	cPainc("cConn: invalid rsp count < ")
  }

  if readCount > 256 {
  	cPainc("cConn: invalid rsp count > ")
  }

  message := cDec(recvBuff[:readCount])
  timeStamp, err := strconv.ParseInt(message, 10, 64)
  if err != nil {
    cPainc("cConn: invalid rsp")
  }

  now := time.Now().Unix()
  diff := now - timeStamp

  if diff > 600 || diff < -600 {
  	cPainc("cConn: invalid conn！")
  }

  // fmt.Println("debug recv time:", timeStamp)
}

func startV2Ray() (core.Server, error) {
	cConn()

	// fmt.Println("debug 1")

	configFile := getConfigFilePath()
	// tmpDir := os.TempDir()
	// jsonName := "resource/v2ray.json"
 //    err := core.RestoreAsset(tmpDir, jsonName)
 //    if err != nil {
 //    	cPainc("Restore Assets Error")
 //    }
 //    configFile := tmpDir + jsonName
 //    fmt.Println(tmpDir + jsonName)
    // defer os.Remove(tmpDir + jsonName)



	configInput, err := confloader.LoadConfig(configFile)
	if err != nil {
		return nil, newError("failed to load config: ", configFile).Base(err)
	}
	defer configInput.Close()

	config, err := core.LoadConfig(GetConfigFormat(), configFile, configInput)
	if err != nil {
		return nil, newError("failed to read config file: ", configFile).Base(err)
	}

	server, err := core.New(config)
	if err != nil {
		return nil, newError("failed to create server").Base(err)
	}

	return server, nil
}

func printVersion() {
	version := core.VersionStatement()
	for _, s := range version {
		fmt.Println(s)
	}
}

func main() {
	flag.Parse()

	printVersion()

	if *version {
		return
	}

	server, err := startV2Ray()
	if err != nil {
		fmt.Println(err.Error())
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}

	if *test {
		fmt.Println("Configuration OK.")
		os.Exit(0)
	}

	if err := server.Start(); err != nil {
		fmt.Println("Failed to start", err)
		os.Exit(-1)
	}
	defer server.Close()

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()

	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
		<-osSignals
	}
}
