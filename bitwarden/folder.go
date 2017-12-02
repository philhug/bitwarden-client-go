package bitwarden

const (
	PATH_FOLDERS = "folders"
)

type FolderService struct {
	client *Client
}

func (c *FolderService) ListFolders() ([]Folder, error) {
	req, err := c.client.newRequest("GET", PATH_FOLDERS, nil)

	folders := make([]Folder, 0)
	data := List{Data: &folders}
	_, err = c.client.do(req, &data)
	if err != nil {
		return nil, err
	}

	return folders, err
}

func (c *FolderService) AddFolder(folder *Folder) (*Folder, error) {
	req, err := c.client.newRequest("POST", PATH_FOLDERS, folder)

	f := Folder{}
	_, err = c.client.do(req, &f)
	if err != nil {
		return nil, err
	}

	return &f, err
}

func (c *FolderService) UpdateFolder(folder *Folder) (*Folder, error) {
	req, err := c.client.newRequest("PUT", PATH_FOLDERS+"/"+folder.Id, folder)

	f := Folder{}
	_, err = c.client.do(req, &f)
	if err != nil {
		return nil, err
	}

	return &f, nil
}

func (c *FolderService) DeleteFolder(folder *Folder) (*Folder, error) {
	req, err := c.client.newRequest("DELETE", PATH_FOLDERS+"/"+folder.Id, folder)

	f := Folder{}
	_, err = c.client.do(req, &f)
	if err != nil {
		return nil, err
	}

	return &f, nil
}
