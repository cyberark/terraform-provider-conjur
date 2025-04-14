package multi_cloud_access_token

type TokenProvider interface {
    Token(clientID string) (string, error)
}