from dataclasses import dataclass, field
@dataclass
class WorkloadPolicy:
    approved_images: set[str]=field(default_factory=set)
    approved_configs: set[str]=field(default_factory=set)
    def check(self,image_digest,config_digest):
        if self.approved_images and image_digest not in self.approved_images: raise PermissionError("image digest not approved")
        if self.approved_configs and config_digest not in self.approved_configs: raise PermissionError("config digest not approved")
Policy=WorkloadPolicy
