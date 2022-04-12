
# Easy crypter based on rsa and aes

Use it secure data exchange. You can encrypt data of any size.



## Usage/Examples

```golang
func main() {
	vas := cryptoplus.Crypter{}
	vas.GenerateKeys()

	ang := cryptoplus.Crypter{}
	ang.GenerateKeys()

	vasKey := vas.GetPublicKey()
	angText := []byte("sss")

	angData, _ := ang.Encrypt(vasKey, angText)

	data, err := vas.Decrypt(angData)

	fmt.Println(err, string(data))
}
```

