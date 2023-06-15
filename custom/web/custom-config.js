config.disableShowMoreStats = true
config.startWithAudioMuted = true
config.disableSpeakerStatsSearch = true
config.startWithVideoMuted = true
config.fileRecordingsServiceSharingEnabled = false
config.liveStreamingEnabled = false
config.preferredTranscribeLanguage = 'de-DE'
config.transcribingEnabled = true
config.transcribeWithAppLanguage = false
config.requireDisplayName = true
config.defaultLocalDisplayName = 'Sie'
config.defaultRemoteDisplayName = 'Zuschauer'
config.defaultLanguage = 'de'
config.enableFeaturesBasedOnToken = true
config.readOnlyName = true
config.gatherStats = false
config.enableDisplayNameInStats = false
config.enableEmailInStats = false

config.disableReactions = true

config.analytics.disabled = true

if (!config.localRecording) {
    config.localRecording = {}
}
config.localRecording.enabled = false

config.hideParticipantsStats = true

if (!config.remoteVideoMenu) {
    config.remoteVideoMenu = {}
}
config.remoteVideoMenu.disableGrantModerator = true

config.disableDeepLinking = true

if (!config.custom) {
    config.custom = {}
}

config.custom.allowViewerToSpeak = false