package response

type IntropectResponse struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope"`
	Subject  string `json:"sub"`
	ClientId string `json:"client_id"`
	UserName string `json:"username"`
	Exp      int64  `json:"exp"`
}
