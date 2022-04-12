<h1>Easy crypter based on rsa and aes</h1>
<code>func main() {
	vas := cryptoplus.Crypter{}
	vas.GenerateKeys()

	ang := cryptoplus.Crypter{}
	ang.GenerateKeys()

	vasKey := vas.GetPublicKey()
	angText := []byte("sss")

	angData, _ := ang.Encrypt(vasKey, angText)

	data, err := vas.Decrypt(angData)

	fmt.Println(err, string(data))
}</code>