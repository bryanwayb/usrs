{
  "targets": [
    {
      "target_name": "users",
      "sources": [
        "src/wrapper.cc",
		"src/users.cc"
      ],
      "conditions": [
        [ "OS == 'mac'", {
          "MACOSX_DEPLOYMENT_TARGET": "10.9",
          "xcode_settings": {
            "OTHER_CPLUSPLUSFLAGS" : [
              "-std=c++11"
            ]
          }
        }],
        [ "OS == 'linux'", {
          "cflags": [
            "-std=c++11"
          ]
        }]
      ]
    }
  ]
}