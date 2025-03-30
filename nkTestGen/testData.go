package nkTestGen

type TestData struct {
	XKeys []XKeysTestData `json:"xkeys"`
}

type XKeysTestData struct {
	Seed1      string `json:"seed1"`
	PK1        string `json:"pk1"`
	Text       string `json:"text"`
	CypherText string `json:"cypher_text"`
	OpenText   string `json:"open_text"`
	Seed2      string `json:"seed2"`
	PK2        string `json:"pk2"`
}
