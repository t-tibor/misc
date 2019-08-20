using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PPTC_skeleton
{
    // Dummy classes to keep the intellisense happy
    class Frame
    {
    }

    // TODO Search a .net component, that can be used as a thread-safe queu
    // containing frame ring buffers
    class FrameRingBufferQueue
    {
    }

    class FrameRingBuffer
    {
        private Frame[] framePool;
        private int capacity;
        private int filledFrameCnt;
        private int StartFrameIdx;
        private int EndFrameIdx;

        public String RecordID;
        // additional sensor level info

        public FrameRingBuffer(int BufferSize)
        {
            // initialize framePool with BufferSize cnt frames

            // initialize index counters

        }

        public Frame SwapFrame(Frame filledFrame)
        {
            // TODO: add the given frame into the ring buffer and return the one being on its place
        }

        public int GetFilledFrameCount()
        {
            // TODO returns the actual full frame count
        }

        public Frame GetFilledFrame(int frameIdx)
        {
            // TODO return the frameIndx-th filled frame (do not remove it, just give the reference back)
        }

        public void Clear()
        {
            // TODO clear the buffer
        }
    }

    
    // This class is responsible for exporting frame ring buffers as a video stream.
    class VideoWriter
    {
        // private members
        private String outputDirectoryPath;
        private String fileNameBase;
        // TODO: OpenCV specific members

        // TODO private FrameRingBufferQueue filledQueue;
        // TODO private FrameRingBufferQueue emptyQueue;

        // constructor
        VideoWriter(String outputDirectoryPath)
        {
            // basic stuff
        }

        public int SaveVideo(FrameRingBuffer filledFrames)
        {
            // TODO save the frames given in the filledFrames buffer as a continuous 
            // video file to the specified output directory.
            // The file name is composed from 3 parts:
            // fileNameBase + '_' + recordID in the ring buffer + '_' + current date

        }

        // TODO This function should be running in a separate thread
        // TODO This function / thread is responsible for getting the filled frame ring buffers
        // from the filledQueue, write their content using the SaveVideo function, and finally  pushing the processes
        // ring buffer back to the empty Queue.
        // If a null reference is read from the queue, the worker thread should exit.
        private void VideoSaverWorker()
        {

        }

        public void StartVideoSaverThread(FrameRingBufferQueue filledQueue, FrameRingBufferQueue emptyQueue)
        {
            // TODO: Start a new thread, that runs the VideoSaverWorker function. Use the queues given as parameters.

            throw new NotImplementedException();
        }

        public void StopVideoSaverThread()
        {
            // TODO push a null reference to the queue, as a signal for thread termination,
            // then join the thread
        }

    }


    // This class is responsible for configuring the camera, processing the recorded frames and forward 
    // the recorded frame buffer to saving.
    class CameraController
    {
        // private object members
        private VideoWriter videoWriter;

        // Vimba specific members

        // general state variables
        private bool isOpened;
        private bool isRunning; // TODO this variable has to be thread safe
        private bool isTriggered; // TODO this variable has to be thread safe

        // public propterty -> the output path where the videos should be saved
        // TODO: check the path existence and access rights in the given folder,
        public String outputPath { get; set; }

        public int WindowLength { get; set; } // TODO general checking
        public int TriggerPosition { get; set; } // TODO check against window length

        // public interface to the GUI / TCPIP thread
        public CameraController()
        {
            // initialize all the members
        }

        public int ConnectToCamera(/* args if needed */)
        {
            // TODO connect to the camera
            // throw exception if no camera is available or if the connection fails

            return -1;
        }

        public int StartCapturing()
        {
            // TODO check global flags 

            // TODO allocate frames into the frame pool

            // TODO create frame ring buffers

            // TODO create videoWriter object 

            // TODO clear the queues

            // TODO push an empty frame ring buffer to the empty queue

            // TODO set the other buffer as  ActualFrameRingBuffer

            // TODO set global flags

            // TODO start the frame streaming
        }

        public int SignalTriggerEvent()
        {
            // This functions signals, that a trigger event has happened
            // TODO: set the isTriggered flag
        }

        public int StopCapturing()
        {
            // TODO set global flags

            // TODO stop frame streaming in the camera

            // TODO stop video writer
        }

        public int DisconectFromCamera()
        {
            StopCapturing();

            // TODO disconnect from camera
        }


        // real time frame processing specific part
        FrameRingBuffer[] FrameRingBuffers;
        FrameRingBuffer ActualFrameRingBuffer;
        private int captureState; // Prefill, WaitForTrigger, Postfill
        private int frameCnt;
        public int droppedFrameRingBuffers;

        private FrameProcessorCallback()
        {
            // This function should be the callback for the VIMBA driver
            // It is responsible for putting the new frame to the ring buffer,
            // and if needed, sending the full ring buffer for saving as a video

            // TODO check global falgs

            // TODO check the incoming frame for errors

            // Create bitmap from the frame and send to the GUI for visualzing

            // TODO put the new fame into the frame ring buffer

            // TODO give the empty frame back to the VIMBA driver

            // TODO handle state transition
            frameCnt++;
            /* switch state
              case Prefill:  
                              if frameCnt >= pre trigger frame count
                                    goto state WaitForTrigger;
              case WaitForTrigger: 
                              if isTriggered
                                    isTriggered  = False
                                    frameCnt =0
                                    goto state Postfill
              case PostFill:
                            if frameCnt >= post  trigger frame cnt
                                SwapFrameRingBuffer()
                                frameCnt = 0
                                isTriggered = 0
                                goto state Prefill
             */
        }

        private int SwapFrameRingBuffer()
        {
            // This functions sends the ActualFrameRingBuffer for saving as a video stream

            // TODO get an empty frame ring buffer from the empty queue
            // If none is available ->we have to drop the actual one, but signal it in the droppedFrameRingBuffers

            // If there is one, push the ActualFrameRingBuffer to the filledQueue, and set the 
            // empty one as ActualFrameRingBuffer                    
        }
    }

    // This class contains the sensor specific infos, filters the trigger events, and create stream id-s.
    class BubbleWatcher
    {
        private CameraController;

    }
    class Program
    {
        static void Main(string[] args)
        {
        }
    }
}
