const DEFAULT_METADATA = [ {
  id: "firstName",
  optional: false,
  displayName: 'First Name',
  description: 'The given name of the user',
  multiValue: false
}, {
  id: "lastName",
  optional: false,
  displayName: 'Last Name',
  description: 'The surname of the user',
  multiValue: false
}, {
  id: "displayName",
  optional: true,
  displayName: 'Display Name',
  description: 'The display name of the user',
  multiValue: false
}, {
  id: "email",
  optional: false,
  displayName: 'E-Mail Address',
  description: 'The e-mail address of the user',
  multiValue: false
},{
  id: "mobilePhone",
  optional: true,
  displayName: 'Mobile Phone',
  description: 'The mobile phone of the user',
  multiValue: false
}, {
  id: "groups",
  optional: true,
  displayName: 'Groups',
  description: 'Group memberships of the user',
  multiValue: true
}]

export default class SimpleProfileMapper {
  private _profile: any;
  private metadata = DEFAULT_METADATA
  constructor(profile: any, metadata?: any) {
    this._profile = profile;
  }

  static fromMetadata = (metadata: any) => {
    CustomProfileMapper.prototype.metadata = metadata
    return CustomProfileMapper;
  }

  public readonly getClaims = () => {
    const self = this;
    const claims: any = {};
  
    this.metadata.forEach((entry: any) => {
      claims[entry.id] = entry.multiValue ?
        self._profile[entry.id].split(',') :
        self._profile[entry.id];
    });
  
    return Object.keys(claims).length && claims;
  }

  public readonly getNameIdentifier = () => ({
    nameIdentifier:                  this._profile.userName,
    nameIdentifierFormat:            this._profile.nameIdFormat,
    nameIdentifierNameQualifier:     this._profile.nameIdNameQualifier,
    nameIdentifierSPNameQualifier:   this._profile.nameIdSPNameQualifier,
    nameIdentifierSPProvidedID:      this._profile.nameIdSPProvidedID
  })
}

class CustomProfileMapper extends SimpleProfileMapper {
  constructor(user: any) {
    super(user)
  }
}

module.exports = SimpleProfileMapper;
