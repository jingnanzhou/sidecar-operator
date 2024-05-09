package v1alpha1

import (
//	appsv1 "k8s.io/api/apps/v1"
//	corev1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +resourceName=sidecars
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// Sidecar describes a Sidecar resource
type Sidecar struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object, including
	// things like...
	//  - name
	//  - namespace
	//  - self link
	//  - labels
	//  - ... etc ...
	meta_v1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the custom resource spec
	Spec SidecarSpec `json:"spec"`
}

// DatasourceSpec is the spec for a Datasource resource
type SidecarSpec struct {

		DataType string `json:"dataType"`

		// Data contains the configuration data.
		// Each key must consist of alphanumeric characters, '-', '_' or '.'.
		// Values with non-UTF-8 byte sequences must use the BinaryData field.
		// The keys stored in Data must not overlap with the keys in
		// the BinaryData field, this is enforced during validation process.
		// +optional
		Data map[string]string `json:"data,omitempty" protobuf:"bytes,2,rep,name=data"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SidecarList is a list of Sidecar resources
type SidecarList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`

	Items []Sidecar `json:"items"`
}
