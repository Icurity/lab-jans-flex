'use strict';

const VERSION = '1.0.0-beta.7';

const DEFAULT_NO_OF_LIVENESS_FRAMES = 8;

function getLivenessFramesIndices(totalNoOfFrames, numberOfFramesRequired = DEFAULT_NO_OF_LIVENESS_FRAMES) {
	const selectedFrames = [];

	if (totalNoOfFrames < numberOfFramesRequired) {
		throw new Error('SmartCameraWeb: Minimum required no of frames is ', numberOfFramesRequired);
	}

	const frameDivisor = numberOfFramesRequired - 1;
	const frameInterval = Math.floor(totalNoOfFrames / frameDivisor);

	// NOTE: when we have satisfied our required 8 frames, but have good
	// candidates, we need to start replacing from the second frame
	let replacementFrameIndex = 1;

	for (let i = 0; i < totalNoOfFrames; i += frameInterval) {
		if (selectedFrames.length < 8) {
			selectedFrames.push(i);
		} else {
			// ACTION: replace frame, then sort selectedframes
			selectedFrames[replacementFrameIndex] = i;
			selectedFrames.sort((a,b) => a - b);

			// ACTION: update replacement frame index
			replacementFrameIndex++;
		}
	}

	// INFO: if we don't satisfy our requirement, we add the last index
	const lastFrameIndex = totalNoOfFrames - 1;

	if (selectedFrames.length < 8 && !selectedFrames.includes(lastFrameIndex)) {
		selectedFrames.push(lastFrameIndex);
	}

	return selectedFrames;
};

const template = document.createElement('template');

template.innerHTML = `
<link rel="preconnect" href="https://fonts.gstatic.com"> 
<link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;700&display=swap" rel="stylesheet">

<style>
	* {
		font-family: 'Nunito Sans', sans-serif;
	}

	[hidden] {
		display: none !important;
	}

	[disabled] {
		cursor: not-allowed !important;
		filter: grayscale(75%);
	}

	.visually-hidden {
		border: 0;
		clip: rect(1px 1px 1px 1px);
		clip: rect(1px, 1px, 1px, 1px);
		height: auto;
		margin: 0;
		overflow: hidden;
		padding: 0;
		position: absolute;
		white-space: nowrap;
		width: 1px;
	}

	img {
		height: auto;
		max-width: 100%;
		transform: scaleX(-1);
	}

	video {
		background-color: black;
		object-fit: cover;
	}

	a {
		color: currentColor;
		text-decoration: none;
	}

	svg {
		max-width: 100%;
	}

	.color-gray {
		color: #797979;
	}

	.color-red {
		color: red;
	}

	.color-richblue {
		color: #4E6577;
	}

	.color-richblue-shade {
		color: #0E1B42;
	}

	.center {
		text-align: center;
		margin-left: auto;
		margin-right: auto;
	}

	.font-size-small {
		font-size: .75rem;
	}

	.font-size-large {
		font-size: 1.5rem;
	}

	.text-transform-uppercase {
		text-transform: uppercase;
	}

	.flow > * + * {
		margin-top: 1rem;
	}

	.button {
		-webkit-appearance: none;
		appearance: none;
		border-radius: 4rem;
		border: 0;
		color: #fff;
		cursor: pointer;
		display: block;
		font-size: 18px;
		font-weight: 600;
		padding: .75rem 1.5rem;
		text-align: center;
	}

	.button--primary {
		background-color: #228B22;
	}

	.button--secondary {
		background-color: #242F40;
	}

	.icon-btn {
		appearance: none;
		background: none;
		border: none;
		color: hsl(0deg 0% 94%);
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 4px 8px;
	}

	.section {
		border: 0px solid #f4f4f4;
		border-radius: .5rem;
		margin-left: auto;
		margin-right: auto;
		max-width: 35ch;
		padding: 1rem;
	}

	.tips,
	.powered-by {
		align-items: center;
		border-radius: .25rem;
		color: #4E6577;
		display: flex;
		justify-content: center;
		letter-spacing: .075em;
	}

	.powered-by {
		box-shadow: 0px 2.57415px 2.57415px rgba(0, 0, 0, 0.06);
		display: inline-flex;
		font-size: .5rem;
	}

	.tips {
		margin-left: auto;
		margin-right: auto;
		max-width: 17rem;
	}

	.tips > * + *,
	.powered-by > * + * {
		display: inline-block;
		margin-left: .5em;
	}

	.powered-by .company {
		color: #18406D;
		font-weight: 700;
		letter-spacing: .15rem;
	}

	.logo-mark {
		background-color: #004071;
		display: inline-block;
		padding: .25em .5em;
	}

	.logo-mark svg {
		height: auto;
		justify-self: center;
		width: .75em;
	}

	@keyframes fadeInOut {
		0% {
			opacity: 0;
		}

		50% {
			opacity: 1;
		}

		100% {
			opacity: 0;
		}
	}

	.video-container,
	.id-video-container {
		position: relative;
		z-index: 1;
		width: 100%;
	}

	.video-container #smile-cta,
	.video-container video,
	.id-video-container video {
		left: 50%;
		min-width: auto;
		position: absolute;
		top: calc(50% - 3px);
		transform: translateX(-50%) translateY(50%);
	}

	.video-container #smile-cta {
		color: white;
		font-size: 2rem;
		font-weight: bold;
		opacity: 0;
		top: calc(50% - 3rem);
	}

	.video-container video {
		min-height: 100%;
		clip-path: ellipse(101px 118px);
		transform: scaleX(-1) translateX(50%) translateY(-50%);
	}

	.id-video-container {
		min-height: calc((2 * 10rem) + 198px);
	}

	.id-video-container .image-frame {
		border-width: 10rem 1rem;
		border-color: rgba(0, 0, 0, 0.7);
		border-style: solid;
		height: auto;
		max-width: 90%;
		position: absolute;
		top: 0;
		left: 0;
		z-index: 2;
	}

	.id-video-container video {
		max-width: 100%;
		max-height: 98%;
		transform: translateX(-50%) translateY(-50%);
		z-index: 1;
	}

	.id-video-container img {
		position: absolute;
		top: 50%;
		left: 50%;
		transform: translateX(-50%) translateY(-50%);
		max-width: 90%;
		max-height: 260px;
	}

	#id-review-screen .image-frame {
		border-color: rgba(0, 0, 0, 1);
	}

	.actions {
		bottom: 0;
		display: flex;
		justify-content: space-between;
		padding: 1rem;
		position: absolute;
		width: 90%;
		z-index: 2;
	}
</style>

<svg hidden fill="none" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 396 259">
	<symbol id="image-frame">
		<path fill-rule="evenodd" clip-rule="evenodd" d="M0 0v69.605h13.349V13.349h56.256V0H0zM396 0h-69.605v13.349h56.256v56.256H396V0zM0 258.604V189h13.349v56.256h56.256v13.348H0zM396 258.604h-69.605v-13.348h56.256V189H396v69.604z" fill="#fff"/>
	</symbol>
</svg>

<svg hidden fill="none" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
	<symbol id="close-icon">
		<path fill-rule="evenodd" clip-rule="evenodd" d="M.732.732a2.5 2.5 0 013.536 0L10 6.464 15.732.732a2.5 2.5 0 013.536 3.536L13.536 10l5.732 5.732a2.5 2.5 0 01-3.536 3.536L10 13.536l-5.732 5.732a2.5 2.5 0 11-3.536-3.536L6.464 10 .732 4.268a2.5 2.5 0 010-3.536z" fill="#fff"/>
	</symbol>
</svg>

<svg hidden fill="none" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 41 41">
	<symbol id="approve-icon">
		<circle cx="20.5" cy="20.5" r="20" stroke="#fff"/>
		<path d="M12.3 20.5l6.15 6.15 12.3-12.3" stroke="#fff" stroke-width="3.075" stroke-miterlimit="10" stroke-linecap="round" stroke-linejoin="round"/>
	</symbol>
</svg>

<svg hidden fill="none" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 17 18">
	<symbol id="refresh-icon">
		<path d="M3.314 15.646a8.004 8.004 0 01-2.217-4.257 8.06 8.06 0 01.545-4.655l1.789.788a6.062 6.062 0 001.264 6.737 6.033 6.033 0 008.551 0c2.358-2.37 2.358-6.224 0-8.592a5.996 5.996 0 00-4.405-1.782l.662 2.354-3.128-.796-3.127-.796 2.25-2.324L7.748 0l.55 1.953a7.966 7.966 0 016.33 2.326 8.004 8.004 0 012.342 5.684 8.005 8.005 0 01-2.343 5.683A7.928 7.928 0 018.97 18a7.928 7.928 0 01-5.656-2.354z" fill="currentColor"/>
	</symbol>
</svg>

<div id='request-screen' class='flow center'>
	<div class='section | flow'>
		<p class='color-red' id='error'>
		</p>

		<!-- <p>
			<a href='https://smileidentity.com' class='powered-by text-transform-uppercase'>
				<span class='logo-mark'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 8 10">
						<symbol id="logo-mark">
							<path fill="#fff" d="M6.67 4V2.82c0-1.65-.9-2.6-2.46-2.6s-2.43.95-2.43 2.6v.3c0 .08.06.13.13.13.08 0 .13-.05.13-.13v-.3c0-.87.3-2.33 2.17-2.33C6.1.5 6.38 1.95 6.38 2.82V4H1.65a.85.85 0 00-.86.83L.97 8.4c0 .45.4.82.87.82h4.51c.47 0 .86-.37.86-.82l.19-3.56A.9.9 0 006.67 4zm.23 4.38c0 .33-.26.55-.57.55h-4.5a.57.57 0 01-.57-.55L1.08 4.8c0-.3.26-.55.57-.55h4.86c.31 0 .57.25.57.55L6.9 8.38z"/>
						</symbol>
						<use href="#logo-mark" />
					</svg>
				</span>
				<span>Powered By</span>
				<span class='company'>Smile Identity</span>
			</a>
		</p> -->

		<p>
			We need access to your camera so that we can take selfie and proof-of-life images.
		</p>

		<button id='request-camera-access' class='button button--primary | center' type='button'>
			Request Camera Access
		</button>
	</div>
</div>

<div hidden id='camera-screen' class='flow center'>
	<h1>Take a Selfie</h1>

	<div class='section | flow'>
		<!-- <p>
			<a href='https://smileidentity.com' class='powered-by text-transform-uppercase'>
				<span class='logo-mark'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 8 10">
						<use href="#logo-mark" />
					</svg>
				</span>
				<span>Powered By</span>
				<span class='company'>Smile Identity</span>
			</a>
		</p> -->

		<div class='video-container'>
			<svg id="image-outline" width="215" height="245" viewBox="0 0 215 245" fill="none" xmlns="http://www.w3.org/2000/svg">
				<path d="M210.981 122.838C210.981 188.699 164.248 241.268 107.55 241.268C50.853 241.268 4.12018 188.699 4.12018 122.838C4.12018 56.9763 50.853 4.40771 107.55 4.40771C164.248 4.40771 210.981 56.9763 210.981 122.838Z" stroke="#17A3DC" stroke-width="7.13965"/>
			</svg>
			<p id='smile-cta' class='color-gray'>SMILE</p>
		</div>

		<small class='tips'>
			<svg width='2.75rem' xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 40 40">
				<path fill="#F8F8FA" fill-rule="evenodd" d="M17.44 0h4.2c4.92 0 7.56.68 9.95 1.96a13.32 13.32 0 015.54 5.54c1.27 2.39 1.95 5.02 1.95 9.94v4.2c0 4.92-.68 7.56-1.95 9.95a13.32 13.32 0 01-5.54 5.54c-2.4 1.27-5.03 1.95-9.95 1.95h-4.2c-4.92 0-7.55-.68-9.94-1.95a13.32 13.32 0 01-5.54-5.54C.68 29.19 0 26.56 0 21.64v-4.2C0 12.52.68 9.9 1.96 7.5A13.32 13.32 0 017.5 1.96C9.89.68 12.52 0 17.44 0z" clip-rule="evenodd"/>
				<path fill="#AEB6CB" d="M19.95 10.58a.71.71 0 000 1.43.71.71 0 000-1.43zm-5.54 2.3a.71.71 0 000 1.43.71.71 0 000-1.43zm11.08 0a.71.71 0 000 1.43.71.71 0 000-1.43zm-5.63 1.27a4.98 4.98 0 00-2.05 9.48v1.2a2.14 2.14 0 004.28 0v-1.2a4.99 4.99 0 00-2.23-9.48zm-7.75 4.27a.71.71 0 000 1.43.71.71 0 000-1.43zm15.68 0a.71.71 0 000 1.43.71.71 0 000-1.43z"/>
			</svg>
			<span>Tips: Put your face inside the oval frame and click to "take selfie"</span> </small>

		<button id='start-image-capture' class='button button--primary | center' type='button'>
			Take Selfie
		</button>
	</div>
</div>

<div hidden id='review-screen' class='flow center'>
	<h1>Review Selfie</h1>

	<div class='section | flow'>
		<img
			alt='your selfie'
			id='review-image'
			src=''
			width='480'
			height='480'
		/>

		<p class='color-richblue-shade font-size-large'>
			Is this clear enough?
		</p>

		<p class='color-gray font-size-small'>
			Make sure your face is clear enough and the photo is not blurry
		</p>

		<button id='select-selfie' class='button button--primary | center' type='button'>
			Yes, use this one
		</button>

		<button id='restart-image-capture' class='button button--secondary | center' type='button'>
			Re-take selfie
		</button>
	</div>
</div>

<div hidden id='id-camera-screen' class='flow center'>
	<h1>Take ID Card Photo</h1>
	<div class='section | flow'>
		<!-- <p>
			<a href='https://smileidentity.com' class='powered-by text-transform-uppercase'>
				<span class='logo-mark'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 8 10">
						<use href="#logo-mark" />
					</svg>
				</span>
				<span>Powered By</span>
				<span class='company'>Smile Identity</span>
			</a>
		</p> -->

		<div class='id-video-container'>
			<svg class="image-frame" fill="none" height="259" width="396" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 396 259">
				<use href='#image-frame' />
			</svg>

			<div class='actions'>
				<button id='capture-id-image' class='button icon-btn | center' type='button'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" height="60" width="60">
						<circle cx="30" cy="30" r="27" stroke="currentColor" stroke-width="3" />
					</svg>
					<span class='visually-hidden'>Capture</span>
				</button>
			</div>
		</div>
	</div>
</div>

<div hidden id='id-review-screen' class='flow center'>
	<h1>Review ID Card</h1>
	<div class='section | flow'>
		<!-- <p>
			<a href='https://smileidentity.com' class='powered-by text-transform-uppercase'>
				<span class='logo-mark'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 8 10">
						<use href="#logo-mark" />
					</svg>
				</span>
				<span>Powered By</span>
				<span class='company'>Smile Identity</span>
			</a>
		</p> -->

		<div class='id-video-container'>
			<svg class="image-frame" fill="none" height="259" width="396" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 396 259">
				<use href='#image-frame' />
			</svg>

			<div class='actions'>
				<button id='select-id-image' class='button icon-btn' type='button'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox='0 0 41 41' height="40" width="40">
						<circle cx="20.5" cy="20.5" r="20" stroke="#fff"/>
						<path d="M12.3 20.5l6.15 6.15 12.3-12.3" stroke="#fff" stroke-width="3.075" stroke-miterlimit="10" stroke-linecap="round" stroke-linejoin="round"/>
					</svg>
					<span class='visually-hidden'>Accept Image</span>
				</button>
				<button id='re-capture-id-image' class='button icon-btn' type='button'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" height="40" width="40" viewBox='0 0 17 18'>
						<path d="M3.314 15.646a8.004 8.004 0 01-2.217-4.257 8.06 8.06 0 01.545-4.655l1.789.788a6.062 6.062 0 001.264 6.737 6.033 6.033 0 008.551 0c2.358-2.37 2.358-6.224 0-8.592a5.996 5.996 0 00-4.405-1.782l.662 2.354-3.128-.796-3.127-.796 2.25-2.324L7.748 0l.55 1.953a7.966 7.966 0 016.33 2.326 8.004 8.004 0 012.342 5.684 8.005 8.005 0 01-2.343 5.683A7.928 7.928 0 018.97 18a7.928 7.928 0 01-5.656-2.354z" fill="currentColor"/>
					</svg>
					<span class='visually-hidden'>Re-Capture</span>
				</button>
			</div>

			<img
				alt='your ID card'
				id='id-review-image'
				src=''
				width='396'
				height='259'
			/>
		</div>
	</div>
</div>

<div hidden id='back-of-id-camera-screen' class='flow center'>
	<h1>Take Back of ID Card Photo</h1>
	<div class='section | flow'>
	<!--	<p>
			<a href='https://smileidentity.com' class='powered-by text-transform-uppercase'>
				<span class='logo-mark'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 8 10">
						<use href="#logo-mark" />
					</svg>
				</span>
				<span>Powered By</span>
				<span class='company'>Smile Identity</span>
			</a>
		</p> -->

		<div class='id-video-container'>
			<svg class="image-frame" fill="none" height="259" width="396" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 396 259">
				<use href='#image-frame' />
			</svg>

			<div class='actions'>
				<button id='capture-back-of-id-image' class='button icon-btn | center' type='button'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" height="60" width="60">
						<circle cx="30" cy="30" r="27" stroke="currentColor" stroke-width="3" />
					</svg>
					<span class='visually-hidden'>Capture</span>
				</button>
			</div>
		</div>
	</div>
</div>

<div hidden id='back-of-id-review-screen' class='flow center'>
	<h1>Review Back of ID Card Photo</h1>
	<div class='section | flow'>
	<!--	<p>
			<a href='https://smileidentity.com' class='powered-by text-transform-uppercase'>
				<span class='logo-mark'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 8 10">
						<use href="#logo-mark" />
					</svg>
				</span>
				<span>Powered By</span>
				<span class='company'>Smile Identity</span>
			</a>
		</p> -->

		<div class='id-video-container'>
			<svg class="image-frame" fill="none" height="259" width="396" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 396 259">
				<use href='#image-frame' />
			</svg>

			<div class='actions'>
				<button id='select-back-of-id-image' class='button icon-btn' type='button'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox='0 0 41 41' height="40" width="40">
						<circle cx="20.5" cy="20.5" r="20" stroke="#fff"/>
						<path d="M12.3 20.5l6.15 6.15 12.3-12.3" stroke="#fff" stroke-width="3.075" stroke-miterlimit="10" stroke-linecap="round" stroke-linejoin="round"/>
					</svg>
					<span class='visually-hidden'>Accept Image</span>
				</button>
				<button id='re-capture-back-of-id-image' class='button icon-btn' type='button'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" height="40" width="40" viewBox='0 0 17 18'>
						<path d="M3.314 15.646a8.004 8.004 0 01-2.217-4.257 8.06 8.06 0 01.545-4.655l1.789.788a6.062 6.062 0 001.264 6.737 6.033 6.033 0 008.551 0c2.358-2.37 2.358-6.224 0-8.592a5.996 5.996 0 00-4.405-1.782l.662 2.354-3.128-.796-3.127-.796 2.25-2.324L7.748 0l.55 1.953a7.966 7.966 0 016.33 2.326 8.004 8.004 0 012.342 5.684 8.005 8.005 0 01-2.343 5.683A7.928 7.928 0 018.97 18a7.928 7.928 0 01-5.656-2.354z" fill="currentColor"/>
					</svg>
					<span class='visually-hidden'>Re-Capture</span>
				</button>
			</div>

			<img
				alt='your ID card'
				id='back-of-id-review-image'
				src=''
				width='396'
				height='259'
			/>
		</div>
	</div>
</div>

<div hidden id='thanks-screen' class='flow center'>
	<div class='section | flow'>
		<h1>Thank you</h1>

	<!--	<p>
			<a href='https://smileidentity.com' class='powered-by text-transform-uppercase'>
				<span class='logo-mark'>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 8 10">
						<use href="#logo-mark" />
					</svg>
				</span>
				<span>Powered By</span>
				<span class='company'>Smile Identity</span>
			</a>
		</p> -->
	</div>
</div>
`;

class SmartCameraWeb extends HTMLElement {
	constructor() {
		super();

		this.attachShadow({ mode: 'open' });
		this.activeScreen = null;
	}

	setActiveScreen(element) {
		this.activeScreen.hidden = true;
		element.hidden = false;
		this.activeScreen = element;
	}

	connectedCallback() {
		if ('mediaDevices' in navigator && 'getUserMedia' in navigator.mediaDevices) {
			this.shadowRoot.appendChild(template.content.cloneNode(true));

			this.shadowRoot.querySelector('#request-camera-access').addEventListener('click', e => this.init(e));
		} else {
			const heading = document.createElement('h1');
			heading.classList.add('error-message');
			heading.textContent = 'Your browser does not support this integration';

			this.shadowRoot.appendChild(heading);
		}
	}

	handleSuccess(stream) {
		const videoExists = !!this.videoContainer.querySelector('video');
		const video = videoExists ? this.videoContainer.querySelector('video') : document.createElement('video');
		const videoTracks = stream.getVideoTracks();

		video.autoplay = true;
		video.playsInline = true;

		if ("srcObject" in video) {
			video.srcObject = stream;
		} else {
			video.src = window.URL.createObjectURL(stream);
		}

		if (!videoExists) this.videoContainer.prepend(video);

		this._data.partner_params.permissionGranted = true;

		this.setActiveScreen(this.cameraScreen);

		this._stream = stream;
		this._video = video;
	}

	handleIDStream(stream) {
		const videoTracks = stream.getVideoTracks();
		const videoExists = this.activeScreen === this.IDCameraScreen ?
			!!this.IDCameraScreen.querySelector('video') :
			!!this.backOfIDCameraScreen.querySelector('video');

		const video = videoExists ? (
			this.activeScreen === this.IDCameraScreen ?
				this.IDCameraScreen.querySelector('video') :
				this.backOfIDCameraScreen.querySelector('video')
			) : document.createElement('video');

		video.autoplay = true;
		video.playsInline = true;

		if ("srcObject" in video) {
			video.srcObject = stream;
		} else {
			video.src = window.URL.createObjectURL(stream);
		}

		if (!videoExists) {
			if (this.activeScreen === this.IDCameraScreen) {
				this.IDCameraScreen.querySelector('.id-video-container').prepend(video);
			} else {
				this.backOfIDCameraScreen.querySelector('.id-video-container').prepend(video);
			}
		}

		this._IDStream = stream;
		this._IDVideo = video;
	}

	handleError(e) {
		if (e.name === 'NotAllowedError' || e.name === 'SecurityError') {
			this.errorMessage.textContent = `
				Looks like camera access was not granted, or was blocked by a browser
				level setting / extension. Please follow the prompt from the URL bar,
				or extensions, and enable access.

				You may need to refresh to start all over again
				`;
		}

		if (e.name === 'AbortError') {
			this.errorMessage.textContent = `
				Oops! Something happened, and we lost access to your stream.

				Please refresh to start all over again
				`;
		}

		if (e.name === 'NotReadableError') {
			this.errorMessage.textContent = `
				There seems to be a problem with your device's camera, or its connection.

				Please check this, and when resolved, try again. Or try another device.
				`;
		}

		if (e.name === 'NotFoundError') {
			this.errorMessage.textContent = `
				We are unable to find a video stream.

				You may need to refresh to start all over again
				`;
		}

		if (e.name === 'TypeError') {
			this.errorMessage.textContent = `
				This site is insecure, and as such cannot have access to your camera.

				Try to navigate to a secure version of this page, or contact the owner.
			`
		}
	}

	init(e) {
		this.errorMessage = this.shadowRoot.querySelector('#error');

		this.captureID = this.hasAttribute('capture-id');
		this.captureBackOfID = this.getAttribute('capture-id') === 'back';

		this.requestScreen = this.shadowRoot.querySelector('#request-screen');
		this.activeScreen = this.requestScreen;
		this.cameraScreen = this.shadowRoot.querySelector('#camera-screen');
		this.reviewScreen = this.shadowRoot.querySelector('#review-screen');
		this.IDCameraScreen = this.shadowRoot.querySelector('#id-camera-screen');
		this.IDReviewScreen = this.shadowRoot.querySelector('#id-review-screen');
		this.backOfIDCameraScreen = this.shadowRoot.querySelector('#back-of-id-camera-screen');
		this.backOfIDReviewScreen = this.shadowRoot.querySelector('#back-of-id-review-screen');
		this.thanksScreen = this.shadowRoot.querySelector('#thanks-screen');

		this.videoContainer = this.shadowRoot.querySelector('.video-container');
		this.smileCTA = this.shadowRoot.querySelector('#smile-cta');
		this.imageOutline = this.shadowRoot.querySelector('#image-outline path');
		this.startImageCapture = this.shadowRoot.querySelector('#start-image-capture');
		this.captureIDImage = this.shadowRoot.querySelector('#capture-id-image');
		this.captureBackOfIDImage = this.shadowRoot.querySelector('#capture-back-of-id-image');
		this.reviewImage = this.shadowRoot.querySelector('#review-image');
		this.IDReviewImage = this.shadowRoot.querySelector('#id-review-image');
		this.backOfIDReviewImage = this.shadowRoot.querySelector('#back-of-id-review-image');

		this.reStartImageCapture = this.shadowRoot.querySelector('#restart-image-capture');
		this.reCaptureIDImage = this.shadowRoot.querySelector('#re-capture-id-image');
		this.reCaptureBackOfIDImage = this.shadowRoot.querySelector('#re-capture-back-of-id-image');
		this.selectSelfie = this.shadowRoot.querySelector('#select-selfie');
		this.selectIDImage = this.shadowRoot.querySelector('#select-id-image');
		this.selectBackOfIDImage = this.shadowRoot.querySelector('#select-back-of-id-image');

		this.startImageCapture.addEventListener('click', () => {
			this._startImageCapture();
		});

		this.selectSelfie.addEventListener('click', () => {
			this._selectSelfie();
		});

		this.selectIDImage.addEventListener('click', () => {
			this._selectIDImage();
		});

		this.selectBackOfIDImage.addEventListener('click', () => {
			this._selectIDImage(true);
		});

		this.captureIDImage.addEventListener('click', () => {
			this._captureIDImage();
		});

		this.captureBackOfIDImage.addEventListener('click', () => {
			this._captureIDImage();
		});

		this.reStartImageCapture.addEventListener('click', () => {
			this._reStartImageCapture();
		});

		this.reCaptureIDImage.addEventListener('click', () => {
			this._reCaptureIDImage();
		});

		this.reCaptureBackOfIDImage.addEventListener('click', () => {
			this._reCaptureIDImage();
		});

		this._videoStreamDurationInMS = 3800;
		this._imageCaptureIntervalInMS = 200;

		this._data = {
			partner_params: {
				libraryVersion: VERSION,
				permissionGranted: false,
			},
			images: []
		};
		this._rawImages = [];

		navigator.mediaDevices.getUserMedia({ audio: false, video: true })
			.then(stream => {
				this.handleSuccess(stream);
			})
			.catch(e => {
				this.handleError(e)
			});
	}

	_startImageCapture() {
		this.startImageCapture.disabled = true;

		/**
		 * this was culled from https://jakearchibald.com/2013/animated-line-drawing-svg/
		 */
		// NOTE: initialise image outline
		const imageOutlineLength = this.imageOutline.getTotalLength();
		// Clear any previous transition
		this.imageOutline.style.transition = 'none';
		// Set up the starting positions
		this.imageOutline.style.strokeDasharray = imageOutlineLength + ' ' + imageOutlineLength;
		this.imageOutline.style.strokeDashoffset = imageOutlineLength;
		// Trigger a layout so styles are calculated & the browser
		// picks up the starting position before animating
		this.imageOutline.getBoundingClientRect();
		// Define our transition
		this.imageOutline.style.transition =
			`stroke-dashoffset ${this._videoStreamDurationInMS / 1000}s ease-in-out`;
		// Go!
		this.imageOutline.style.strokeDashoffset = '0';

		this.smileCTA.style.animation = `fadeInOut ease ${this._videoStreamDurationInMS / 1000}s`;

		this._imageCaptureInterval = setInterval(() => {
			this._capturePOLPhoto();
		}, this._imageCaptureIntervalInMS);

		this._videoStreamTimeout = setTimeout(() => {
			this._stopVideoStream(this._stream);
		}, this._videoStreamDurationInMS);
	}

	_captureIDImage() {
		const canvas = document.createElement('canvas');
		canvas.width = 1024;
		canvas.height = 576;

		const context = this._drawIDImage(canvas);

		const image = canvas.toDataURL('image/jpeg');

		if (this.activeScreen === this.IDCameraScreen) {
			this.IDReviewImage.src = image;
		} else {
			this.backOfIDReviewImage.src = image;
		}

		this._data.images.push({
			image_type_id: this.activeScreen === this.IDCameraScreen ? 3 : 7,
			image: image.split(',')[1]
		});

		this._stopIDVideoStream();

		if (this.activeScreen === this.IDCameraScreen) {
			this.setActiveScreen(this.IDReviewScreen);
		} else {
			this.setActiveScreen(this.backOfIDReviewScreen);
		}
	}

	_drawImage(canvas, video = this._video) {
		const context = canvas.getContext('2d');

		const imageDimension = 240;

		const xCenterOfImage = video.videoWidth / 2;
		const yCenterOfImage = video.videoHeight / 2

		context.drawImage(
			video,
			(xCenterOfImage - (imageDimension / 2)), (yCenterOfImage - (imageDimension / 2)),
			imageDimension, imageDimension,
			0, 0,
			canvas.width, canvas.height
		);

		return context;
	}

	_drawIDImage(canvas, video = this._IDVideo) {
		const context = canvas.getContext('2d');

		const aspectRatio = video.videoWidth / video.videoHeight;

		// NOTE: aspectRatio is greater than 1 in landscape mode, less in portrait
		if (aspectRatio < 1) {
			const cropHeight = video.videoWidth * aspectRatio;

			context.drawImage(
				video,
				0, ((video.videoHeight - cropHeight) / 2),
				video.videoWidth, cropHeight,
				0, 0,
				canvas.width, canvas.height
			);
		} else {
			context.drawImage(video, 0, 0, canvas.width, canvas.height);
		}

		return context;
	}

	_capturePOLPhoto() {
		const canvas = document.createElement('canvas');
		canvas.width = 144;
		canvas.height = 144;

		const contextWithImage = this._drawImage(canvas);

		const imageData = contextWithImage.getImageData(0, 0, canvas.width, canvas.height);
		// NOTE: this gives us access to rgba values
		let data = imageData.data;

		// NOTE: we loop over every 4 elements because pixel data is stored in
		// 4 indexes
		for (let i = 0; i < data.length; i += 4) {
			// NOTE: This section converts the pixels in the image to Greyscale
			// Step 1: Get color channels
			var r = data[i]; // Red Channel
			var g = data[i + 1]; // Green Channel
			var b = data[i + 2]; // Blue Channel

			// Step 2: Compute greyscale image using a luminousity based weighted average method
			// ref: https://goodcalculators.com/rgb-to-grayscale-conversion-calculator/
			var brightness = 0.299 * r + 0.587 * g + 0.114 * b;

			// ACTION: Replace all channels to grey-scale value
			data[i] = brightness;
			data[i + 1] = brightness;
			data[i + 2] = brightness;
		}

		contextWithImage.putImageData(imageData, 0, 0);

		this._rawImages.push(canvas.toDataURL('image/jpeg'));
	}

	_captureReferencePhoto() {
		const canvas = document.createElement('canvas');
		canvas.width = 480;
		canvas.height = 480;

		const context = this._drawImage(canvas);

		const image = canvas.toDataURL('image/jpeg');

		this._referenceImage = image;

		this._data.images.push({
			image_type_id: 2,
			image: image.split(',')[1]
		});
	}

	_stopVideoStream(stream) {
		clearTimeout(this._videoStreamTimeout);
		clearInterval(this._imageCaptureInterval);
		clearInterval(this._drawingInterval);
		this.smileCTA.style.animation = 'none';

		this._capturePOLPhoto(); // NOTE: capture the last photo
		this._captureReferencePhoto();
		stream.getTracks().forEach(track => track.stop());

		this.reviewImage.src = this._referenceImage;

		const totalNoOfFrames = this._rawImages.length;

		const livenessFramesIndices = getLivenessFramesIndices(totalNoOfFrames);

		this._data.images = this._data.images.concat(livenessFramesIndices.map(imageIndex => ({
			image_type_id: 6,
			image: this._rawImages[imageIndex].split(',')[1],
		})));

		this.setActiveScreen(this.reviewScreen);
	}

	_stopIDVideoStream(stream = this._IDStream) {
		stream.getTracks().forEach(track => track.stop());
	}

	async _startIDCamera() {
		try {
			const stream = await navigator.mediaDevices.getUserMedia({
				audio: false,
				video: { facingMode: 'environment', width: { min: 1280 } }
			});

			this.handleIDStream(stream);
		} catch (e) {
			this.handleError(e);
		}
	}

	_selectSelfie() {
		if (!this.captureID) {
			this._publishSelectedImages();
		} else {
			this.setActiveScreen(this.IDCameraScreen);
			this._startIDCamera();
		}
	}

	_selectIDImage(backOfIDCaptured = false) {
		if (!this.captureBackOfID || backOfIDCaptured) {
			this._publishSelectedImages();
		} else {
			this.setActiveScreen(this.backOfIDCameraScreen);
			this._startIDCamera();
		}
	}

	_publishSelectedImages() {
		this.dispatchEvent(
			new CustomEvent('imagesComputed', { detail: this._data })
		);

		this.setActiveScreen(this.thanksScreen);
	}

	async _reStartImageCapture() {
		this.startImageCapture.disabled = false;

		this._data.images = [];

		try {
			const stream = await navigator.mediaDevices.getUserMedia({
				audio: false,
				video: true
			});

			this.handleSuccess(stream);
		} catch (e) {
			this.handleError(e);
		}
	}

	async _reCaptureIDImage() {
		if (this.activeScreen === this.IDReviewScreen) {
			this.setActiveScreen(this.IDCameraScreen);
		} else {
			this.setActiveScreen(this.backOfIDCameraScreen);
		}

		// NOTE: removes the last element in the list
		this._data.images.pop();

		try {
			const stream = await navigator.mediaDevices.getUserMedia({
				audio: false,
				video: { facingMode: 'environment', width: { min: 1280 } }
			});

			this.handleIDStream(stream);
		} catch (e) {
			this.handleError(e);
		}
	}
}

window.customElements.define('smart-camera-web', SmartCameraWeb);
