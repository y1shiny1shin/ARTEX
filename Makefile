# RyAgent platform helpers.
JAVA_HOME    ?= /Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home
ANDROID_HOME ?= $(HOME)/Library/Android/sdk
ADB          ?= /Applications/MuMuPlayer.app/Contents/MacOS/MuMuEmulator.app/Contents/MacOS/tools/adb
APK          := app/android/app/build/outputs/apk/release/app-release.apk

.PHONY: help bff bff-run app-release app-install app-debug test clean

help:
	@echo "make bff          build BFF"
	@echo "make bff-run      run BFF locally (reads ARTEX_BASE_URL + tmp secrets)"
	@echo "make app-release  build Android release APK"
	@echo "make app-install  install release APK on MuMu"
	@echo "make test         BFF/P0 checks"
	@echo "make clean        remove local build outputs"

bff:
	cd bff && GOWORK=off go build -o bin/ryagent-bff ./cmd/ryagent-bff

bff-run: bff
	cd bff && ./run-local.sh

app-release:
	cd app/android && JAVA_HOME=$(JAVA_HOME) ANDROID_HOME=$(ANDROID_HOME) ANDROID_SDK_ROOT=$(ANDROID_HOME) \
	  ./gradlew assembleRelease --no-daemon -PreactNativeArchitectures=x86_64,arm64-v8a

app-install:
	$(ADB) connect 127.0.0.1:16384
	$(ADB) -s 127.0.0.1:16384 install -r $(APK)
	$(ADB) -s 127.0.0.1:16384 shell am start -n com.y1shin.ryagent/.MainActivity

app-debug:
	cd app/android && JAVA_HOME=$(JAVA_HOME) ANDROID_HOME=$(ANDROID_HOME) ANDROID_SDK_ROOT=$(ANDROID_HOME) \
	  ./gradlew assembleDebug --no-daemon -PreactNativeArchitectures=x86_64

test:
	cd bff && GOWORK=off go test ./...
	cd app && npx tsc --noEmit

clean:
	rm -rf bff/bin bff/data app/android/.gradle app/android/build app/android/app/build
