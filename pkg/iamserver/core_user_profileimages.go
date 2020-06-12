package iamserver

import (
	"io"
	"path"

	"github.com/kadisoka/foundation/pkg/errors"
	"github.com/kadisoka/foundation/pkg/media"
	mediapb "github.com/rez-go/crux-apis/crux/media/v1"

	"github.com/citadelium/iam/pkg/iam"
)

type ProfileImageFile interface {
	io.Reader
	io.Seeker
}

func (core *Core) SetUserProfileImageByFile(
	callCtx iam.CallContext,
	userID iam.UserID,
	imageFile ProfileImageFile,
) (imageURL string, err error) {
	detectionBytes := make([]byte, 512)
	_, err = imageFile.Read(detectionBytes)
	if err != nil {
		return "", errors.Wrap("file read", err)
	}
	imageFile.Seek(0, io.SeekStart)

	const bucketSubPath = "user_profile_images/"
	mediaTypeInfo := media.GetMediaTypeInfo(mediapb.MediaType_IMAGE)
	if mediaTypeInfo == nil {
		return "", errors.Msg("media type info unavailable")
	}
	contentType := media.DetectType(detectionBytes)

	if !mediaTypeInfo.IsContentTypeAllowed(contentType) {
		return "", errors.ArgMsg("imageFile", "media type not allowed")
	}

	filename := core.mediaStore.GenerateName(imageFile)
	imageFile.Seek(0, io.SeekStart)

	publicURL, err := core.mediaStore.
		Upload(
			path.Join(bucketSubPath, filename),
			imageFile,
			mediaTypeInfo.MediaType())
	if err != nil {
		return "", errors.Wrap("file store", err)
	}

	err = core.SetUserProfileImageURL(callCtx, userID, publicURL)
	if err != nil {
		return "", errors.Wrap("user profile image URL update", err)
	}

	return publicURL, nil
}
