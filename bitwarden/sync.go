package bitwarden

const (
	PATH_SYNC = "sync"
)

type SyncService struct {
	client *Client
}

func (c *SyncService) GetSync() (SyncData, error) {
	req, err := c.client.newRequest("GET", PATH_SYNC, nil)

	var syncData SyncData
	_, err = c.client.do(req, &syncData)

	return syncData, err
}
