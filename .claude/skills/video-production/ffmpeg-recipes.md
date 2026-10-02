# ffmpeg recipes

Tested on this machine with ffmpeg 9.0.1 (Homebrew): libx264, aac, mov_text, loudnorm, xfade and
overlay available; drawtext and subtitles are not. Work in `factory/demos/<M>/video/raw/<clip>/`.
`V=factory/demos/<M>/video` below.

## 1. Narration per beat (draft voice)

```bash
for f in $V/narration/<clip>/*.txt; do
  n=$(basename "$f" .txt)
  say -v Samantha -r 170 -f "$f" -o "$V/raw/<clip>/vo-$n.aiff"
  ffmpeg -y -v error -i "$V/raw/<clip>/vo-$n.aiff" -ar 48000 -ac 2 "$V/raw/<clip>/vo-$n.wav"
done
# Beat durations (ms) for the recording script; pad each beat by 600 ms of breathing room.
for w in $V/raw/<clip>/vo-*.wav; do
  n=$(basename "$w" .wav | sed 's/vo-//')
  d=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$w")
  echo "\"$n\": $(python3 -c "print(int($d*1000)+600)")"
done | paste -sd, - | sed 's/^/{/; s/$/}/' > $V/raw/<clip>/beats.json
```

## 2. Transcode the Playwright take

```bash
ffmpeg -y -v error -i take-1.webm -r 30 -c:v libx264 -crf 16 -preset slow -pix_fmt yuv420p take-1.mp4
```

## 3. Title card PNG → video segment (matching format, with silent audio)

```bash
ffmpeg -y -v error -loop 1 -t 3 -i card-00.png -f lavfi -t 3 -i anullsrc=r=48000:cl=stereo \
  -vf "scale=1920:1080,format=yuv420p,fade=in:st=0:d=0.2,fade=out:st=2.8:d=0.2" -r 30 \
  -c:v libx264 -crf 16 -c:a aac -b:a 192k -shortest card-00.mp4
```

## 4. Narration track for the recorded body

Concatenate the beat audio in order (the recording already holds each beat for its audio
length + 600 ms, so pad each file to its beat length):

```bash
for w in vo-*.wav; do ffmpeg -y -v error -i "$w" -af "apad=pad_dur=0.6" "pad-$w"; done
ls pad-vo-*.wav | sed "s/.*/file '&'/" > vo.txt
ffmpeg -y -v error -f concat -safe 0 -i vo.txt -c pcm_s16le vo-all.wav
ffmpeg -y -v error -i take-1.mp4 -i vo-all.wav -map 0:v -map 1:a -c:v copy -c:a aac -b:a 192k -shortest body.mp4
```

Trim a take: `ffmpeg -ss 00:00:01.200 -to 00:01:28.000 -i body.mp4 -c:v libx264 -crf 16 -c:a aac body-trim.mp4`
(re-encode when trimming so cuts are frame-accurate).

## 5. Join cards and body

All segments must share size, frame rate, pixel format and audio layout (they do if made by the
recipes above):

```bash
printf "file '%s'\n" card-00.mp4 body.mp4 card-99.mp4 > parts.txt
ffmpeg -y -v error -f concat -safe 0 -i parts.txt -c copy joined.mp4
```

A 200 ms crossfade between two segments instead of a cut (offset = first duration − 0.2):

```bash
ffmpeg -y -v error -i a.mp4 -i b.mp4 -filter_complex \
 "[0:v][1:v]xfade=transition=fade:duration=0.2:offset=2.8[v];[0:a][1:a]acrossfade=d=0.2[a]" \
 -map "[v]" -map "[a]" -c:v libx264 -crf 16 -c:a aac ab.mp4
```

## 6. Loudness, captions, presets

```bash
# master: −16 LUFS, soft captions, archive quality
ffmpeg -y -v error -i joined.mp4 -i ../../captions/<clip>.srt \
  -map 0:v -map 0:a -map 1 -c:v libx264 -crf 18 -preset slow -profile:v high -pix_fmt yuv420p -r 30 \
  -af "loudnorm=I=-16:TP=-1.5:LRA=11" -c:a aac -ar 48000 -b:a 192k \
  -c:s mov_text -metadata:s:s:0 language=eng -movflags +faststart <clip>-master.mp4

# web: from the master
ffmpeg -y -v error -i <clip>-master.mp4 -map 0 -c:v libx264 -crf 23 -preset slow -c:a aac -b:a 160k \
  -c:s copy -movflags +faststart ../../clips/<clip>.mp4

# preview: 720p
ffmpeg -y -v error -i <clip>-master.mp4 -map 0 -vf scale=1280:720 -c:v libx264 -crf 28 -c:a aac -b:a 128k \
  -c:s copy -movflags +faststart <clip>-preview.mp4

# 15-second style sample from 00:12
ffmpeg -y -v error -ss 12 -t 15 -i <clip>-master.mp4 -map 0:v -map 0:a -vf scale=1280:720 \
  -c:v libx264 -crf 23 -c:a aac -b:a 128k -movflags +faststart a.mp4
```

Single-pass `loudnorm` can miss on short clips with long silences (a 10 s test landed at
−14.6 LUFS). If the check below is outside −16 ±1, run two-pass: first
`-af loudnorm=I=-16:TP=-1.5:LRA=11:print_format=json -f null -`, then pass the printed
`measured_I/TP/LRA/thresh` and `offset` back as `measured_I=…:measured_TP=…:measured_LRA=…:measured_thresh=…:offset=…:linear=true`.

## 7. Checks

```bash
ffprobe -v error -show_entries stream=codec_type,codec_name,width,height,r_frame_rate -of compact <file>
ffmpeg -hide_banner -i <file> -af ebur128=framelog=quiet -f null - 2>&1 | grep -A2 'Integrated loudness'
```

`.srt` format reminder: `1` / `00:00:03,000 --> 00:00:06,400` / text (≤ 42 chars × 2 lines) /
blank line.
