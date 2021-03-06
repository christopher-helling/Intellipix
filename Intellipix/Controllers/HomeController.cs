﻿using ImageResizer;
using Microsoft.ApplicationInsights;
using Intellipix.Models;
using Microsoft.ProjectOxford.Vision;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Security.Claims;

namespace Intellipix.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            // Pass a list of blob URIs in ViewBag
            CloudStorageAccount account = CloudStorageAccount.Parse(ConfigurationManager.AppSettings["StorageConnectionString"]);
            CloudBlobClient client = account.CreateCloudBlobClient();
            CloudBlobContainer container = client.GetContainerReference("photos");
            List<BlobInfo> blobs = new List<BlobInfo>();

            foreach (IListBlobItem item in container.ListBlobs())
            {
                var blob = item as CloudBlockBlob;

                if (blob != null)
                {
                    blob.FetchAttributes(); // Get blob metadata
                    var caption = blob.Metadata.ContainsKey("Caption") ? blob.Metadata["Caption"] : blob.Name;

                    blobs.Add(new BlobInfo()
                    {
                        ImageUri = blob.Uri.ToString(),
                        ThumbnailUri = blob.Uri.ToString().Replace("/photos/", "/thumbnails/"),
                        Caption = caption
                    });
                }
            }

            ViewBag.Blobs = blobs.ToArray();
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Oops" + CauseAnError();
            return View();
        }

        public ActionResult Contact()
        {
            var client = new TelemetryClient();
            client.TrackEvent("Contact Information Was Requested");
            ViewBag.Message = "Your contact page.";
            return View();
        }

        [HttpPost]
        [Authorize]
        public async Task<ActionResult> Upload(HttpPostedFileBase file)
        {
            if (file != null && file.ContentLength > 0)
            {
                // Make sure the user selected an image file
                if (!file.ContentType.StartsWith("image"))
                {
                    TempData["Message"] = "Only image files may be uploaded";
                }
                else
                {
                    try
                    {
                        // Save the original image in the "photos" container
                        CloudStorageAccount account = CloudStorageAccount.Parse(ConfigurationManager.AppSettings["StorageConnectionString"]);
                        CloudBlobClient client = account.CreateCloudBlobClient();
                        CloudBlobContainer container = client.GetContainerReference("photos");
                        CloudBlockBlob photo = container.GetBlockBlobReference(Path.GetFileName(file.FileName));
                        await photo.UploadFromStreamAsync(file.InputStream);

                        // Generate a thumbnail and save it in the "thumbnails" container
                        using (var outputStream = new MemoryStream())
                        {
                            file.InputStream.Seek(0L, SeekOrigin.Begin);
                            var settings = new ResizeSettings { MaxWidth = 192 };
                            ImageBuilder.Current.Build(file.InputStream, outputStream, settings);
                            outputStream.Seek(0L, SeekOrigin.Begin);
                            container = client.GetContainerReference("thumbnails");
                            CloudBlockBlob thumbnail = container.GetBlockBlobReference(Path.GetFileName(file.FileName));
                            await thumbnail.UploadFromStreamAsync(outputStream);
                        }

                        // Submit the image to Azure's Computer Vision API
                        VisionServiceClient vision = new VisionServiceClient(
                            ConfigurationManager.AppSettings["SubscriptionKey"],
                            ConfigurationManager.AppSettings["VisionEndpoint"]
                        );

                        VisualFeature[] features = new VisualFeature[] { VisualFeature.Description };
                        var result = await vision.AnalyzeImageAsync(photo.Uri.ToString(), features);

                        // Record the ID of the user who uploaded this photo
                        var objectIdentifierClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";
                        photo.Metadata.Add("Owner", ClaimsPrincipal.Current.FindFirst(objectIdentifierClaim).Value);

                        // Record the image description and tags in blob metadata
                        photo.Metadata.Add("Caption", result.Description.Captions[0].Text);

                        for (int i = 0; i < result.Description.Tags.Length; i++)
                        {
                            string key = String.Format("Tag{0}", i);
                            photo.Metadata.Add(key, result.Description.Tags[i]);
                        }

                        await photo.SetMetadataAsync();
                    }
                    catch (Exception ex)
                    {
                        // In case something goes wrong
                        TempData["Message"] = ex.Message;
                    }
                }
            }

            return RedirectToAction("Index");
        }

        public ActionResult Error(string message)
        {
            // Don't actually pass ViewBag message directly to user, this is a security risk
            // This is just for testing the sample project
            ViewBag.ErrorMessage = message;
            return View();
        }

        private int CauseAnError()
        {
            // Force an unhandled exception
            System.Diagnostics.Trace.TraceWarning("Something bad is about to happen.");
            var numerator = 0;
            var denominator = 0;
            return numerator / denominator;
        }

    }
}